package policy

import (
	"runtime"
	"sync"

	"github.com/op/go-logging"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

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
type MacIpInportKey uint64 // u64(mac) . u32(ip) . u32(RxInterface)
type ServiceKey uint64     // u20(group_id) . u8(proto) . u16(port)
type PolicyKey uint64      // u20(group_id) . u20(service_id) . u12(vlan_id)

type GroupId uint32
type ServiceId uint32
type PolicyId uint32

type PolicyDataBlock = [1024]PolicyData

type PolicyTable struct {
	cloudPlatformData *CloudPlatformData
	policyLabel       *PolicyLabel

	policyDataPoll sync.Pool
	block          *PolicyDataBlock
	blockCursor    int
}

type PolicyCounter struct {
	Acl      uint32 `statsd:"acl"`
	FastPath uint32 `statsd:"fast_path"`

	MacTable   uint32 `statsd:"mac_table"`
	IpTable    uint32 `statsd:"ip_table"`
	EpcIpTable uint32 `statsd:"epc_ip_table"`
	FastTable  uint32 `statsd:"fast_table"`
	ArpTable   uint32 `statsd:"arp_table"`
}

func NewPolicyTable(actionTypes ActionType) *PolicyTable { // 传入Protobuf结构体指针
	// 使用actionTypes过滤，例如
	// Trident仅关心PACKET_BROKER和PACKET_STORE，
	// 那么就不要将EPC等云平台信息进行计算。
	// droplet关心**几乎**所有，对关心的信息进行计算
	policyTable := &PolicyTable{
		cloudPlatformData: NewCloudPlatformData(),
		policyLabel:       NewPolicyLabel(),
	}
	policyTable.policyDataPoll.New = func() interface{} {
		block := new(PolicyDataBlock)
		runtime.SetFinalizer(block, func(b *PolicyDataBlock) { policyTable.policyDataPoll.Put(b) })
		return block
	}
	policyTable.block = policyTable.policyDataPoll.Get().(*PolicyDataBlock)
	return policyTable
}

func (t *PolicyTable) alloc() *PolicyData {
	policyData := &t.block[t.blockCursor]
	t.blockCursor++
	if t.blockCursor >= len(t.block) {
		t.block = t.policyDataPoll.Get().(*PolicyDataBlock)
		*t.block = PolicyDataBlock{}
		t.blockCursor = 0
	}
	return policyData
}

func (t *PolicyTable) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(t.cloudPlatformData.macTable.macMap)),
		EpcIpTable: uint32(len(t.cloudPlatformData.epcIpTable.epcIpMap)),
	}

	for i := 0; i < MASK_LEN; i++ {
		counter.IpTable += uint32(len(t.cloudPlatformData.ipTables[i].ipMap))
	}
	for i := TAP_ANY; i < TAP_MAX; i++ {
		counter.Acl += uint32(len(t.policyLabel.aclData[i]))
		counter.FastPath += uint32(t.policyLabel.fastPath[i].fastPolicy.Len())
		counter.FastTable += uint32(t.cloudPlatformData.fastPath[i].fastPlatform.Len())
		counter.ArpTable += uint32(len(t.cloudPlatformData.arpTable[i].arpMap))
	}
	return counter
}

// Trident用于PACKET_BROKER、PACKET_STORE
func (t *PolicyTable) LookupActionByKey(key *LookupKey) *PolicyData {
	// 将匹配策略的所有Action merge以后返回
	// FIXME: 注意将查找过程中的性能监控数据发送到statsd
	return nil
}

// River用于PACKET_BROKER，Stream用于FLOW_STORE
func (t *PolicyTable) LookupActionByPolicyId(policyId PolicyId) *PolicyData {
	// FIXME
	return nil
}

func (t *PolicyTable) GetPolicyDataByFastPath(endpointData *EndpointData, key *LookupKey, fastKey *FastKey) *PolicyData {
	fastKey.Ports = uint64(key.SrcPort<<32) | uint64(key.DstPort)
	fastKey.ProtoVlan = uint64(key.Proto<<32) | uint64(key.Vlan)
	policyData := t.policyLabel.GetPolicyByFastPath(fastKey, key.Tap)
	if policyData == nil {
		policyData = t.GetPolicyData(endpointData, key)
		t.policyLabel.InsertPolicyToFastPath(fastKey, policyData, key.Tap)
	}
	return policyData
}

func (t *PolicyTable) GetPolicyData(endpointData *EndpointData, key *LookupKey) *PolicyData {
	policyData := t.alloc()
	if aclActions := t.policyLabel.GetPolicyData(endpointData, key); aclActions != nil {
		for _, aclAction := range aclActions {
			policyData.Merge(aclAction)
		}
	}

	return policyData
}

// Droplet用于ANALYTIC_*、PACKET_BROKER、PACKET_STORE
func (t *PolicyTable) LookupAllByKey(key *LookupKey) (*EndpointData, *PolicyData) {
	if !key.Tap.CheckTapType(key.Tap) {
		return NewEndpointData(), t.alloc()
	}
	endpointData, fastKey := t.cloudPlatformData.GetEndpointData(key)
	if key.Tap == TAP_TOR {
		endpointData.SetL2End(key)
	}
	policyData := t.GetPolicyDataByFastPath(endpointData, key, fastKey)
	return endpointData, policyData
}

func (t *PolicyTable) UpdateInterfaceData(data []*PlatformData) {
	t.cloudPlatformData.UpdateInterfaceTable(data)
}

func (t *PolicyTable) UpdateIpGroupData(data []*IpGroupData) {
	t.cloudPlatformData.ipGroup.Update(data)
}

func (t *PolicyTable) UpdateAclData(data []*Acl) {
	t.policyLabel.UpdateAcls(data)
}

func (t *PolicyTable) GetEndpointInfo(mac uint64, ip uint32, inPort uint32) *EndpointInfo {
	var endpointInfo *EndpointInfo
	if PortInDeepflowExporter(inPort) {
		endpointInfo = t.cloudPlatformData.GetEndpointInfo(mac, ip, TAP_TOR)
	} else {
		endpointInfo = t.cloudPlatformData.GetEndpointInfo(mac, ip, TAP_ISP)
	}

	return endpointInfo
}
