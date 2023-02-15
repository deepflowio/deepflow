/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy

import (
	"net"
	"sort"

	logging "github.com/op/go-logging"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type SortedAcls []*Acl
type SortedIpGroups []*IpGroupData

var log = logging.MustGetLogger("policy")

/*
查询逻辑：160~640~920ns + 160ns*N_group
 1. 分别查询源端、目的端的如下信息：160~640~920ns + 80ns*N_group
    1.1. 根据MAC和IP组成MacIpKey，查询endPointCache：80~320~460ns
    1.1.1. 若Cache命中，则直接获取EndpointInfo：0ns
    1.1.2. 若Cache未命中：240~380ns
    1.1.2.1. 根据MAC查询macMap，获取EndpointInfo：80ns
    1.1.2.2. 根据EPC_ID和IP组成EpcIpKey查询epcIpMap，获取EndpointInfo，与上一步的结果合并：80ns
    1.1.2.3. 根据EPC_ID和IP组成EpcIpKey查询ipGroupCache：80~220ns
    1.1.2.3.1. 若Cache命中，则直接获取EndpointInfo，并与上一步的结果合并：0ns
    1.1.2.3.2. 若Cache未命中，则使用EpcIpKey查询ipGroupTree，并与上一步的结果合并：140ns
    1.2. 遍历GroupIds，与proto、port组成ServiceKey，查询serviceMap：80ns*n_group
    1.2.1. 通过interest_proto和interest_port数组避免肯定没有结果的查询
    1.3. 根据TTL修复L3End（FIXME：如何避免首包L3End错误）
 2. 根据源端、目的端信息，获取PolicyId：80ns*N_group
    2.1. 使用源端GroupId、目的端ServiceId、VLAN组成PolicyKey，查询policyMap，获取PolicyId
    2.2. 使用源端ServiceId、目的端GroupId、VLAN组成PolicyKey，查询policyMap，获取PolicyId
 3. 通过PolicyId找到Action
 4. 合并Action，返回
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

	ACL_PROTO_MAX = 256
)

var STANDARD_NETMASK = MaskLenToNetmask(STANDARD_MASK_LEN)

type TableID int

const (
	DDBS TableID = iota
)

type TableCreator func(queueCount, level int, mapSize uint32, fastPathDisable bool) TableOperator

var tableCreator = [...]TableCreator{
	DDBS: NewDdbs,
}

type TableOperator interface {
	GetHitStatus() (uint64, uint64)
	GetCounter() interface{}

	AddAcl(acl *Acl)
	DelAcl(id int)
	GetAcl() []*Acl
	FlushAcls()
	UpdateAcls(data []*Acl, check ...bool) error
	UpdateInterfaceData(data []PlatformData)
	UpdateIpGroupData(data []*IpGroupData)
	UpdateCidr(data []*Cidr)
	UpdateMemoryLimit(memoryLimit uint64)

	SetCloudPlatform(cloudPlatformLabeler *CloudPlatformLabeler)

	GetPolicyByFirstPath(*LookupKey, *PolicyData, *EndpointData) *EndpointStore
	GetPolicyByFastPath(*LookupKey, *PolicyData) *EndpointStore

	// 目前是从statsd监控中移除
	Close()
}

type PolicyTable struct {
	cloudPlatformLabeler *CloudPlatformLabeler
	operator             TableOperator

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
	FirstPathItems       uint64 `statsd:"first_path_items"`
	FirstPathMaxBucket   uint32 `statsd:"first_path_max_bucket"`
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

func NewPolicyTable(queueCount, level int, mapSize uint32, fastPathDisable bool, ids ...TableID) *PolicyTable { // 传入Protobuf结构体指针
	availableMapSize := getAvailableMapSize(queueCount, mapSize)
	policyTable := &PolicyTable{
		cloudPlatformLabeler: NewCloudPlatformLabeler(queueCount, availableMapSize),
		queueCount:           queueCount,
	}

	id := DDBS
	if len(ids) > 0 {
		id = ids[0]
	}
	policyTable.operator = tableCreator[id](queueCount, level, mapSize, fastPathDisable)
	policyTable.operator.SetCloudPlatform(policyTable.cloudPlatformLabeler)
	return policyTable
}

func (t *PolicyTable) GetHitStatus() (uint64, uint64) {
	return t.operator.GetHitStatus()
}

func (t *PolicyTable) AddAcl(acl *Acl) {
	t.operator.AddAcl(acl)
}

func (t *PolicyTable) DelAcl(id int) {
	t.operator.DelAcl(id)
}

func (t *PolicyTable) GetAcl() []*Acl {
	return t.operator.GetAcl()
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

func (t *PolicyTable) Close() {
	t.operator.Close()
}

func (t *PolicyTable) GetCounter() interface{} {
	return t.operator.GetCounter()
}

func (t *PolicyTable) LookupAllByKey(key *LookupKey, policy *PolicyData, endpoint *EndpointData) {
	if !key.TapType.CheckTapType(key.TapType) {
		*policy = *INVALID_POLICY_DATA
		*endpoint = *INVALID_ENDPOINT_DATA
		return
	}
	store := t.operator.GetPolicyByFastPath(key, policy)
	if store == nil {
		var endpointData *EndpointData
		if key.L3EpcId0 != 0 {
			// 目前droplet使用该场景，droplet目前不关注VIP Device等信息，这里不做初始化
			endpointData = &EndpointData{
				SrcInfo: &EndpointInfo{L2End: key.L2End0, L3End: key.L3End0, L3EpcId: int32(int16(key.L3EpcId0))},
				DstInfo: &EndpointInfo{L2End: key.L2End1, L3End: key.L3End1, L3EpcId: int32(int16(key.L3EpcId1))}}
		} else {
			endpointData = t.cloudPlatformLabeler.GetEndpointData(key)
		}

		store = t.operator.GetPolicyByFirstPath(key, policy, endpointData)
	}
	result := t.cloudPlatformLabeler.UpdateEndpointData(store, key)
	*endpoint = *result
}

func (t *PolicyTable) UpdateInterfaceData(data []PlatformData) {
	t.cloudPlatformLabeler.UpdateInterfaceTable(data)
	t.operator.UpdateInterfaceData(data)
}

func (t *PolicyTable) UpdateIpGroupData(data []*IpGroupData) {
	t.operator.UpdateIpGroupData(data)
}

func (t *PolicyTable) UpdatePeerConnection(data []*PeerConnection) {
	t.cloudPlatformLabeler.UpdatePeerConnectionTable(data)
}

func (t *PolicyTable) UpdateCidrs(data []*Cidr) {
	t.operator.UpdateCidr(data)
}

func (t *PolicyTable) UpdateAclData(data []*Acl, check ...bool) error {
	return t.operator.UpdateAcls(data, check...)
}

func (t *PolicyTable) EnableAclData() {
	t.operator.FlushAcls()
}

func (t *PolicyTable) UpdateMemoryLimit(limit uint64) {
	t.operator.UpdateMemoryLimit(limit)
}

// 该函数仅用于测试或命令行使用
func (t *PolicyTable) GetEndpointInfo(mac uint64, ip net.IP, inPort uint32) *EndpointInfo {
	var endpointInfo *EndpointInfo
	if PortInDeepflowExporter(inPort) {
		endpointInfo, _ = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_CLOUD, false, 0)
	} else {
		endpointInfo, _ = t.cloudPlatformLabeler.GetEndpointInfo(mac, ip, TAP_IDC_MIN, false, 0)
	}

	return endpointInfo
}

// 测试使用
func (t *PolicyTable) GetPolicyByFastPath(key *LookupKey) (*EndpointData, *PolicyData) {
	policy := new(PolicyData)
	endpoint := t.operator.GetPolicyByFastPath(key, policy)
	if endpoint == nil {
		return INVALID_ENDPOINT_DATA, INVALID_POLICY_DATA
	}
	return endpoint.Endpoints, policy
}

// 测试使用
func (t *PolicyTable) GetPolicyByFirstPath(key *LookupKey) (*EndpointData, *PolicyData) {
	policy := new(PolicyData)
	endpoint := t.cloudPlatformLabeler.GetEndpointData(key)
	store := t.operator.GetPolicyByFirstPath(key, policy, endpoint)
	return store.Endpoints, policy
}

// 测试使用
func (t *PolicyTable) lookupAllByKey(key *LookupKey) (*EndpointData, *PolicyData) {
	policy, endpoint := &PolicyData{}, &EndpointData{}
	t.LookupAllByKey(key, policy, endpoint)
	return endpoint, policy
}
