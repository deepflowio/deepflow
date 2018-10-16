package policy

import (
	"sort"
	"sync"
	"sync/atomic"

	logging "github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type SortedAcls []*Acl

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
	sync.Mutex
	cloudPlatformLabeler *CloudPlatformLabeler
	policyLabeler        *PolicyLabeler

	queueCount int
}

type PolicyCounter struct {
	Acl      uint32 `statsd:"acl"`
	FastPath uint32 `statsd:"fast_path"`

	MacTable   uint32 `statsd:"mac_table"`
	IpTable    uint32 `statsd:"ip_table"`
	EpcIpTable uint32 `statsd:"epc_ip_table"`
	FastTable  uint32 `statsd:"fast_table"`
	ArpTable   uint32 `statsd:"arp_table"`

	FastHit  uint64 `statsd:"fast_hit"`
	FirstHit uint64 `statsd:"first_hit"`

	AclHitMax uint64 `statsd:"acl_hit_max"`
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
	// Trident仅关心PACKET_RAW_BROKERING和PACKET_CAPTURING，
	// 那么就不要将EPC等云平台信息进行计算。
	// droplet关心**几乎**所有，对关心的信息进行计算
	availableMapSize := getAvailableMapSize(queueCount, mapSize)
	policyTable := &PolicyTable{
		cloudPlatformLabeler: NewCloudPlatformLabeler(queueCount, availableMapSize),
		policyLabeler:        NewPolicyLabeler(queueCount, availableMapSize, fastPathDisable),
		queueCount:           queueCount,
	}
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

func (t *PolicyTable) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(t.cloudPlatformLabeler.macTable.macMap)),
		EpcIpTable: uint32(len(t.cloudPlatformLabeler.epcIpTable.epcIpMap)),
	}

	for i := 0; i < MASK_LEN; i++ {
		counter.IpTable += uint32(len(t.cloudPlatformLabeler.ipTables[i].ipMap))
	}

	for i := 0; i < t.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			counter.FastPath += uint32(t.policyLabeler.FastPolicyMaps[i][j].Len())
		}
	}

	counter.FastHit = atomic.SwapUint64(&t.policyLabeler.FastPathHitTick, 0)
	counter.FirstHit = atomic.SwapUint64(&t.policyLabeler.FirstPathHitTick, 0)

	counter.Acl += uint32(len(t.policyLabeler.RawAcls))
	for i := TAP_MIN; i < TAP_MAX; i++ {
		counter.ArpTable += uint32(len(t.cloudPlatformLabeler.arpTable[i].arpMap))
	}
	counter.AclHitMax = atomic.SwapUint64(&t.policyLabeler.AclHitMax, 0)
	return counter
}

// Trident用于PACKET_RAW_BROKERING和PACKET_CAPTURING
func (t *PolicyTable) LookupActionByKey(key *LookupKey) *PolicyData {
	// 将匹配策略的所有Action merge以后返回
	// FIXME: 注意将查找过程中的性能监控数据发送到statsd
	return nil
}

// River用于PACKET_RAW_BROKERING，Stream用于PACKET_CAPTURING
func (t *PolicyTable) LookupActionByPolicyId(policyId PolicyId) *PolicyData {
	// FIXME
	return nil
}

// Droplet用于*_COUNTING、PACKET_RAW_BROKERING、PACKET_CAPTURING
func (t *PolicyTable) LookupAllByKey(key *LookupKey) (*EndpointData, *PolicyData) {
	if !key.Tap.CheckTapType(key.Tap) {
		return INVALID_ENDPOINT_DATA, INVALID_POLICY_DATA
	}

	endpoint, policy := t.policyLabeler.GetPolicyByFastPath(key)
	if endpoint == nil {
		endpoint = t.cloudPlatformLabeler.GetEndpointData(key)
		policy = t.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	}
	return endpoint, policy
}

func (t *PolicyTable) UpdateInterfaceData(data []*PlatformData) {
	t.cloudPlatformLabeler.UpdateInterfaceTable(data)
	t.policyLabeler.GenerateIpNetmaskMapFromPlatformData(data)
}

func (t *PolicyTable) UpdateIpGroupData(data []*IpGroupData) {
	t.cloudPlatformLabeler.UpdateGroupTree(data)
	t.policyLabeler.GenerateIpNetmaskMapFromIpGroupData(data)
}

func (t *PolicyTable) UpdateAclData(data []*Acl) {
	t.policyLabeler.UpdateAcls(data)
}

func (t *PolicyTable) EnableAclData() {
	t.policyLabeler.FlushAcls()
}

func (t *PolicyTable) GetEndpointInfo(mac uint64, ip uint32, inPort uint32) *EndpointInfo {
	endpointInfo := (*EndpointInfo)(nil)
	if PortInDeepflowExporter(inPort) {
		endpointInfo = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_TOR)
	} else {
		endpointInfo = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_ISP)
	}

	return endpointInfo
}
