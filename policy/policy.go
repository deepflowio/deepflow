package policy

import (
	"github.com/op/go-logging"
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

type ActionType uint32

const (
	ACTION_PACKET_STAT ActionType = 1 << iota
	ACTION_FLOW_STAT
	ACTION_FLOW_PERF
	ACTION_PACKET_STORE
	ACTION_FLOW_STORE
	ACTION_PACKET_BROKER
)

type TapType uint8

const (
	TAP_ISP TapType = 1 + iota
	TAP_SPINE
	TAP_TOR
)

type Action struct {
	ActionTypes ActionType // bitwise OR
	PolicyIds   []PolicyId
	// FIXME: packet brocker action list
}

func (l *Action) merge(r *Action) {
	l.ActionTypes |= r.ActionTypes
	// FIXME: PolicyId merge
	// FIXME: packet brocker list merge
}

type EndpointInfo struct {
	L2EpcId      int32 // -1表示其它项目
	L2DeviceType uint32
	L2DeviceId   uint32

	L3End        bool
	L3EpcId      int32 // -1表示其它项目
	L3DeviceType uint32
	L3DeviceId   uint32

	HostIp   uint32
	SubnetId uint32
	GroupIds []uint32
}

type EndpointData struct {
	SrcInfo *EndpointInfo
	DstInfo *EndpointInfo
}

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

const (
	MAX_GROUP_ID   = 1 << 20
	MAX_SERVICE_ID = 1 << 20
	MAX_POLICY_ID  = 1 << 20
)

type PolicyTable struct {
	cloudPlatformData *CloudPlatformData
	policyMap         map[PolicyKey]PolicyId // 策略字典
	serviceTable      *ServiceTable
	policyAction      [MAX_POLICY_ID]*Action
}

func NewPolicyTable( /* 传入Protobuf结构体指针 */ actionTypes ActionType) *PolicyTable {
	/* 使用actionTypes过滤，例如
	 * Trident仅关心PACKET_BROKER和PACKET_STORE，
	 * 那么就不要将EPC等云平台信息进行计算。
	 * droplet关心**几乎**所有，对关心的信息进行计算*/
	return &PolicyTable{
		cloudPlatformData: NewCloudPlatformData(),
		serviceTable:      NewSerivceTable(),
	}
}

type LookupKey struct {
	SrcMac, DstMac   uint64
	SrcIp, DstIp     uint32
	SrcPort, DstPort uint16
	Vlan             uint16
	Proto            uint8
	Ttl              uint8
	RxInterface      uint32
	Tap              TapType
}

// Trident用于PACKET_BROKER、PACKET_STORE
func (t *PolicyTable) LookupActionByKey(key *LookupKey) *Action {
	// 将匹配策略的所有Action merge以后返回
	// FIXME: 注意将查找过程中的性能监控数据发送到statsd
	return nil
}

// River用于PACKET_BROKER，Stream用于FLOW_STORE
func (t *PolicyTable) LookupActionByPolicyId(policyId PolicyId) *Action {
	// FIXME
	return nil
}

// Droplet用于ANALYTIC_*、PACKET_BROKER、PACKET_STORE
func (t *PolicyTable) LookupAllByKey(key *LookupKey) (*EndpointData, *Action) {
	// FIXME: 注意利用TTL更新L3End（仅当用于ANALYTIC_*时）
	endpointData := t.cloudPlatformData.GetEndpointData(key)
	serviceIds := t.serviceTable.GetServiceId(endpointData, key)
	if serviceIds != nil {
		//FIXME 添加policy实现
		log.Debug("SERVICEIDS:", serviceIds)
	}
	return endpointData, nil
}

func (t *PolicyTable) UpdateServiceData(data []*ServiceData) {
	if data != nil {
		t.serviceTable.UpdateServiceTable(data)
	}
}

func (t *PolicyTable) UpdateInterfaceData(data []*PlatformData) {
	if data != nil {
		t.cloudPlatformData.UpdateInterfaceTable(data)
	}
}

func (t *PolicyTable) UpdateIpGroupData(data []*IpGroupData) {
	if data != nil {
		t.cloudPlatformData.ipGroup.Update(data)
	}
}

func (t *PolicyTable) GetEndpointInfo(mac uint64, ip uint32, inPort uint32) *EndpointInfo {
	return t.cloudPlatformData.GetEndpointInfo(mac, ip, inPort)
}
