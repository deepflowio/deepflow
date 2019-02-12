package policy

import (
	"sort"
	"sync/atomic"

	logging "github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type SortedAcls []*Acl
type SortedIpGroups []*IpGroupData

var log = logging.MustGetLogger("policy")

/*
查询逻辑：160~640~920ns + 160ns*N_group
- 分别查询源端、目的端的如下信息：160~640~920ns + 80ns*N_group
  - 根据MAC和IP组成MacIpKey，查询endPointCache：80~320~460ns
    - 若Cache命中，则直接获取EndpointInfo：0ns
    - 若Cache未命中：240~380ns
      - 根据MAC查询macMap，获取EndpointInfo：80ns
      - 根据EPC_ID和IP组成EpcIpKey查询epcIpMap，获取EndpointInfo，与上一步的结果合并：80ns
      - 根据EPC_ID和IP组成EpcIpKey查询ipGroupCache：80~220ns
        - 若Cache命中，则直接获取EndpointInfo，并与上一步的结果合并：0ns
	- 若Cache未命中，则使用EpcIpKey查询ipGroupTree，并与上一步的结果合并：140ns
  - 遍历GroupIds，与proto、port组成ServiceKey，查询serviceMap：80ns*n_group
    - 通过interest_proto和interest_port数组避免肯定没有结果的查询
  - 根据TTL修复L3End（FIXME：如何避免首包L3End错误）
- 根据源端、目的端信息，获取PolicyId：80ns*N_group
  - 使用源端GroupId、目的端ServiceId、VLAN组成PolicyKey，查询policyMap，获取PolicyId
  - 使用源端ServiceId、目的端GroupId、VLAN组成PolicyKey，查询policyMap，获取PolicyId
- 通过PolicyId找到Action
- 合并Action，返回
*/
type MacKey uint64         // u64(mac)
type IpKey uint32          // u32(ip)
type EpcIpKey uint64       // u32(epc_id) . u32(ip)
type MacIpKey uint64       // u64(mac) . u32(ip)
type MacIpInportKey uint64 // u64(mac) . u32(ip) . u32(Tap)
type ServiceKey uint64     // u20(group_id) . u8(proto) . u16(port)
type PolicyKey uint64      // u20(group_id) . u20(service_id) . u12(vlan_id)

type GroupId uint32
type ServiceId uint32
type PolicyId uint32

const (
	MIN_FASTPATH_MAP_LEN = 1 << 10
	MAX_FASTPATH_MAP_LEN = 1 << 20
)

type PolicyTable struct {
	cloudPlatformLabeler *CloudPlatformLabeler
	policyLabeler        *PolicyLabeler

	queueCount int
}

type PolicyCounter struct {
	MacTable   uint32 `statsd:"mac_table"`
	EpcIpTable uint32 `statsd:"epc_ip_table"`
	IpTable    uint32 `statsd:"ip_table"`
	ArpTable   uint32 `statsd:"arp_table"`

	Acl                  uint32 `statsd:"acl"`
	FirstHit             uint64 `statsd:"first_hit"`
	FastHit              uint64 `statsd:"fast_hit"`
	AclHitMax            uint32 `statsd:"acl_hit_max"`
	FastPath             uint32 `statsd:"fast_path"`
	FastPathMacCount     uint32 `statsd:"fast_path_mac_count"`
	FastPathPolicyCount  uint32 `statsd:"fast_path_policy_count"`
	UnmatchedPacketCount uint64 `statsd:"unmatched_packet_count"`
}

func getAvailableMapSize(queueCount int, mapSize uint32) uint32 {
	availableMapSize := uint32(MAX_FASTPATH_MAP_LEN)
	newMapSize := mapSize / uint32(queueCount)
	if availableMapSize > newMapSize {
		availableMapSize = uint32(MIN_FASTPATH_MAP_LEN)
		for availableMapSize < newMapSize {
			availableMapSize <<= 1
		}
	}
	return availableMapSize
}

func NewPolicyTable(actionFlags ActionFlag, queueCount int, mapSize uint32, fastPathDisable bool) *PolicyTable { // 传入Protobuf结构体指针
	// 使用actionFlags过滤，例如
	// Trident仅关心PACKET_BROKERING和PACKET_CAPTURING，
	// 那么就不要将EPC等云平台信息进行计算。
	// droplet关心**几乎**所有，对关心的信息进行计算
	availableMapSize := getAvailableMapSize(queueCount, mapSize)
	policyTable := &PolicyTable{
		cloudPlatformLabeler: NewCloudPlatformLabeler(queueCount, availableMapSize),
		policyLabeler:        NewPolicyLabeler(queueCount, availableMapSize, fastPathDisable),
		queueCount:           queueCount,
	}
	policyTable.policyLabeler.cloudPlatformLabeler = policyTable.cloudPlatformLabeler
	return policyTable
}

func (t *PolicyTable) GetHitStatus() (uint64, uint64) {
	return atomic.LoadUint64(&t.policyLabeler.FirstPathHit), atomic.LoadUint64(&t.policyLabeler.FastPathHit)
}

func (t *PolicyTable) AddAcl(acl *Acl) {
	t.policyLabeler.AddAcl(acl)
}

func (t *PolicyTable) DelAcl(id int) {
	t.policyLabeler.DelAcl(id)
}

func (t *PolicyTable) GetAcl() []*Acl {
	return t.policyLabeler.RawAcls
}

func (acls SortedAcls) Len() int {
	return len(acls)
}

func (acls SortedAcls) Less(i, j int) bool {
	return acls[i].Id < acls[j].Id
}

func (acls SortedAcls) Swap(i, j int) {
	acls[i], acls[j] = acls[j], acls[i]
}

func SortAclsById(acls []*Acl) []*Acl {
	sort.Sort(SortedAcls(acls))
	return acls
}

func (ipGroups SortedIpGroups) Len() int {
	return len(ipGroups)
}

func (ipGroups SortedIpGroups) Less(i, j int) bool {
	return ipGroups[i].Id < ipGroups[j].Id
}

func (ipGroups SortedIpGroups) Swap(i, j int) {
	ipGroups[i], ipGroups[j] = ipGroups[j], ipGroups[i]
}

func SortIpGroupsById(ipGroups []*IpGroupData) []*IpGroupData {
	sort.Sort(SortedIpGroups(ipGroups))
	return ipGroups
}

func (t *PolicyTable) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(t.cloudPlatformLabeler.macTable.macMap)),
		EpcIpTable: uint32(len(t.cloudPlatformLabeler.epcIpTable.epcIpMap)),
	}
	for i := MIN_MASK_LEN; i < MAX_MASK_LEN; i++ {
		counter.IpTable += uint32(len(t.cloudPlatformLabeler.ipTables[i].ipMap))
	}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		counter.ArpTable += uint32(len(t.cloudPlatformLabeler.arpTable[i]))
	}

	counter.Acl += uint32(len(t.policyLabeler.RawAcls))
	counter.FirstHit = atomic.SwapUint64(&t.policyLabeler.FirstPathHitTick, 0)
	counter.FastHit = atomic.SwapUint64(&t.policyLabeler.FastPathHitTick, 0)
	counter.AclHitMax = atomic.SwapUint32(&t.policyLabeler.AclHitMax, 0)
	counter.FastPathMacCount = atomic.LoadUint32(&t.policyLabeler.FastPathMacCount)
	counter.FastPathPolicyCount = atomic.LoadUint32(&t.policyLabeler.FastPathPolicyCount)
	counter.UnmatchedPacketCount = atomic.LoadUint64(&t.policyLabeler.UnmatchedPacketCount)
	for i := 0; i < t.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			maps := t.policyLabeler.FastPolicyMaps[i][j]
			mapsMini := t.policyLabeler.FastPolicyMapsMini[i][j]
			if maps != nil {
				counter.FastPath += uint32(maps.Len())
			}
			if mapsMini != nil {
				counter.FastPath += uint32(mapsMini.Len())
			}
		}
	}
	return counter
}

// River用于PACKET_BROKERING，Stream用于PACKET_CAPTURING
func (t *PolicyTable) LookupActionByPolicyId(policyId PolicyId) *PolicyData {
	// FIXME
	return nil
}

// Droplet用于*_COUNTING、PACKET_BROKERING、PACKET_CAPTURING
// FIXME: tricky argument
func (t *PolicyTable) LookupAllByKey(key *LookupKey) (*EndpointData, *PolicyData) {
	if !key.Tap.CheckTapType(key.Tap) {
		return INVALID_ENDPOINT_DATA, INVALID_POLICY_DATA
	}
	endpoint, policy := t.policyLabeler.GetPolicyByFastPath(key)
	if policy == nil {
		endpoint = t.cloudPlatformLabeler.GetEndpointData(key)
		endpoint, policy = t.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	}
	if key.HasFeatureFlag(NPM) {
		endpoint = t.cloudPlatformLabeler.UpdateEndpointData(endpoint, key)
	}
	return endpoint, policy
}

func (t *PolicyTable) UpdateInterfaceData(data []*PlatformData) {
	t.cloudPlatformLabeler.UpdateInterfaceTable(data)
	t.policyLabeler.GenerateIpNetmaskMapFromPlatformData(data)
	t.policyLabeler.generateGroupIdMapByPlatformData(data)
}

func (t *PolicyTable) UpdateIpGroupData(data []*IpGroupData) {
	t.cloudPlatformLabeler.UpdateGroupTree(data)
	t.policyLabeler.GenerateIpNetmaskMapFromIpGroupData(data)
	t.policyLabeler.generateGroupIdMapByIpGroupData(data)
}

func (t *PolicyTable) UpdateAclData(data []*Acl) {
	t.policyLabeler.UpdateAcls(data)
}

func (t *PolicyTable) EnableAclData() {
	t.policyLabeler.FlushAcls()
}

func (t *PolicyTable) GetEndpointInfo(mac uint64, ip uint32, inPort uint32) *EndpointInfo {
	var endpointInfo *EndpointInfo
	if PortInDeepflowExporter(inPort) {
		endpointInfo = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_TOR)
	} else {
		endpointInfo = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_ISP)
	}

	return endpointInfo
}

func (t *PolicyTable) GetPolicyByFastPath(key *LookupKey) (*EndpointData, *PolicyData) {
	endpoint, policy := t.policyLabeler.GetPolicyByFastPath(key)
	if endpoint == nil {
		return INVALID_ENDPOINT_DATA, INVALID_POLICY_DATA
	}
	return endpoint, policy
}

func (t *PolicyTable) GetPolicyByFirstPath(key *LookupKey) (*EndpointData, *PolicyData) {
	endpoint := t.cloudPlatformLabeler.GetEndpointData(key)
	endpoint, policy := t.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	return endpoint, policy
}
