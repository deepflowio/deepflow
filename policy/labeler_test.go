package policy

import (
	"reflect"
	"testing"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

var (
	forward       = AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
	backward      = AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddDirections(BACKWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
	ip1           = NewIPFromString("192.168.2.12").Int()
	ip2           = NewIPFromString("192.168.2.0").Int()
	ip3           = NewIPFromString("192.168.0.11").Int()
	ip4           = NewIPFromString("192.168.0.12").Int()
	mac1          = NewMACAddrFromString("08:00:27:a4:2b:fc").Int()
	mac2          = NewMACAddrFromString("08:00:27:a4:2b:fa").Int()
	launchServer1 = NewIPFromString("10.10.10.10").Int()
)

func (policy *PolicyTable) UpdateAcls(acl []*Acl) {
	policy.UpdateAclData(acl)
	policy.EnableAclData()
}

func getBackwardAcl(acl AclAction) AclAction {
	return acl.SetDirections(BACKWARD)
}

func CheckPolicyResult(basicPolicy *PolicyData, targetPolicy *PolicyData) bool {
	return reflect.DeepEqual(basicPolicy, targetPolicy)
}

func CheckEndpointDataResult(basicSrcInfo, basicDstInfo *EndpointInfo, targetEndpoint *EndpointData) bool {
	return (reflect.DeepEqual(basicSrcInfo, targetEndpoint.SrcInfo)) &&
		(reflect.DeepEqual(basicDstInfo, targetEndpoint.DstInfo))
}

func generateIpNet(ip uint32, subnetId uint32, mask uint32) *IpNet {
	ipInfo := IpNet{
		Ip:       ip,
		SubnetId: subnetId,
		Netmask:  mask,
	}
	return &ipInfo
}

func generateIpGroup(groupId uint32, epcId int32, ip string) *IpGroupData {
	ipgroup := IpGroupData{
		Id:    groupId,
		EpcId: epcId,
	}
	ipgroup.Ips = append(ipgroup.Ips, ip)
	return &ipgroup
}

// 生成特定IP资源组信息
func generateIpgroupData(policy *PolicyTable) {
	ipGroup1 := generateIpGroup(2, 11, "192.168.0.11/24")
	ipGroup2 := generateIpGroup(3, 11, "192.168.0.11/24")
	ipGroup3 := generateIpGroup(4, 12, "192.168.0.11/24")

	ipGroups := make([]*IpGroupData, 0, 3)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3)
	policy.UpdateIpGroupData(ipGroups)
}

func generatePlatformDataExtension(epcId int32, deviceType, deviceId, ifType, ifIndex uint32, mac uint64, hostIp uint32) *PlatformData {
	data := PlatformData{
		EpcId:      epcId,
		DeviceType: deviceType,
		DeviceId:   deviceId,
		IfType:     ifType,
		IfIndex:    ifIndex,
		Mac:        mac,
		HostIp:     hostIp,
	}
	return &data
}

// 生成特定平台信息
func generatePlatformData(policy *PolicyTable) {
	ipInfo := generateIpNet(ip3, 121, 32)

	vifData := generatePlatformDataExtension(11, 1, 3, 4, 5, mac1, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo)

	var datas []*PlatformData
	datas = append(datas, vifData)
	policy.UpdateInterfaceData(datas)
}

func TestGetPlatformData(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// ecpId:11 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac1 HostIp:launchServer1
	vifData := generatePlatformDataExtension(11, 2, 3, 3, 5, mac1, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	ipInfo2 := generateIpNet(ip2, 125, 24)
	ipInfo3 := generateIpNet(ip1, 126, 32)
	vifData1 := generatePlatformDataExtension(0, 1, 100, 3, 5, mac2, launchServer1)
	vifData1.Ips = append(vifData1.Ips, ipInfo2, ipInfo3)

	var datas []*PlatformData
	datas = append(datas, vifData, vifData1)
	policy.UpdateInterfaceData(datas)

	key := generateLookupKey(mac1, mac2, 0, ip1, ip3, 0, 0, 0)
	result, _ := policy.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
}

func TestGetPlatformDataAboutArp(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	key := &LookupKey{
		SrcIp:   ip1,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip3,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// ecpId:11 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac1 HostIp:launchServer1
	vifData := generatePlatformDataExtension(11, 2, 3, 3, 5, mac1, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	datas := make([]*PlatformData, 0, 2)
	datas = append(datas, vifData)
	policy.UpdateInterfaceData(datas)
	now := time.Now()
	result, _ := policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	now = time.Now()
	result, _ = policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
}

func TestGetGroupData(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	now := time.Now()
	result, _ := policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	now = time.Now()
	result, _ = policy.LookupAllByKey(key)
	t.Log(time.Now().Sub(now))
}

//测试全局Pass策略匹配direction==3
func TestAllPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 0, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试资源组forward策略匹配 direction==1
func TestGroupForwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// srcGroups: 3
	acl1 := generatePolicyAcl(policy, forward, 10, 3, 0, 0, 0, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试资源组backward策略匹配 direction==2
func TestGroupBackwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstGroups: 3
	acl1 := generatePolicyAcl(policy, backward, 10, 0, 3, 0, 0, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Port策略匹配 acl配置port=0，查询SrcPort=30，DstPort=30，查询到ACl
func TestAllPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 30, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		SrcPort: 30,
		DstPort: 30,
		EthType: EthernetTypeARP,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Port策略匹配 acl配置port=30，查询Srcport=30，查到acl的direction=2
func TestSrcPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts : 30
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 30, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		SrcPort: 30,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Port策略匹配 acl配置port=30，查询Dstport=30，查到acl的direction=1
func TestDstPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 30, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 30,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Port策略匹配 acl配置port=30，查询SrcPort=30, Dstport=30，查到acl的direction=3
func TestSrcDstPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 30, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 30,
		SrcPort: 30,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Vlan策略匹配 acl配置Vlan=30，查询Vlan=30, 查询到Acl
func TestVlanPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 0, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 30,
		SrcPort: 30,
		Vlan:    30,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Vlan策略匹配 acl配置Vlan=0，Port=8000,查询Vlan=30,Port=8000 查询到Acl
func TestVlanPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 8000, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 30,
		SrcPort: 8000,
		Vlan:    30,
		Ttl:     64,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试Vlan策略匹配 acl配置Proto=6，Port=8000,查询Proto=6,Port=8000 查询到Acl
func TestPortProtoPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 6, 8000, 0)
	policy.UpdateAcls([]*Acl{acl1})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 8000,
		SrcPort: 8000,
		Vlan:    30,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试两条acl proto为6和17 查询proto=6的acl,proto为6的匹配成功
func TestAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 17, 8000, 0)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 8000,
		SrcPort: 8000,
		Vlan:    30,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试两条acl vlan为10和0  查询vlan=10的策略，结果两条都能匹配
func TestVlanAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 8000
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 8000, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 8000,
		SrcPort: 8000,
		Vlan:    10,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)

	aclAction2 = aclAction2.SetDirections(FORWARD)
	aclAction2Backward := aclAction2
	aclAction2Backward.SetDirections(BACKWARD)

	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, aclAction2Backward, forward, backward}, 20)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试两条acl vlan=10和port=8000  查询vlan=10,port=1000，匹配到vlan=10的策略
func TestVlanPortAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 1000,
		Vlan:    10,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	backward := getBackwardAcl(aclAction2)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, backward}, 20)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试两条acl vlan=10和port=8000  查询vlan=10,port=8000，两条策略都匹配到
func TestVlanPortAclsPassPolicy1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 8000
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 8000,
		Vlan:    10,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	acl2Backward := getBackwardAcl(aclAction2)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, acl2Backward, forward}, 20)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

//测试两条acl vlan=10和port=8000  查询port=8000，匹配到port=8000的策略
func TestVlanPortAclsPassPolicy2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := &LookupKey{
		SrcIp:   ip3,
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   ip4,
		EthType: EthernetTypeARP,
		DstPort: 8000,
		Ttl:     64,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	_, policyData = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

func generatePlatformDataByParam(strIp, StrMac string, epcId int32, Iftype uint32) *PlatformData {
	ip := NewIPFromString(strIp)
	ipInfo := generateIpNet(ip.Int(), 121, 32)

	mac := NewMACAddrFromString(StrMac)
	launchServer := NewIPFromString("10.10.10.10")
	vifData := generatePlatformDataExtension(epcId, 1, 3, Iftype, 5, mac.Int(), launchServer.Int())
	vifData.Ips = append(vifData.Ips, ipInfo)
	return vifData
}

// 生成特定Acl规则
func generateAclData(policy *PolicyTable) {
	dstPorts := []uint16{8000}
	aclAction1 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl1 := &Acl{
		Id:       10,
		Type:     TAP_TOR,
		TapId:    11,
		DstPorts: dstPorts,
		Proto:    6,
		Vlan:     0,
		Action:   []AclAction{aclAction1},
	}
	aclAction2 := AclAction(0).AddActionFlags(ACTION_PACKET_COUNTING).AddTagTemplates(TEMPLATE_EDGE_PORT)
	acl2 := &Acl{
		Id:     20,
		Type:   TAP_TOR,
		TapId:  11,
		Proto:  6,
		Vlan:   10,
		Action: []AclAction{aclAction2},
	}
	policy.UpdateAclData([]*Acl{acl1, acl2})
}

type EpcInfo struct {
	L2EpcId0 int32
	L3EpcId0 int32
	L2EpcId1 int32
	L3EpcId1 int32
}

func CheckEpcTestResult(epcInfo *EpcInfo, endpointData *EndpointData) bool {
	return (epcInfo.L2EpcId0 == endpointData.SrcInfo.L2EpcId) &&
		(epcInfo.L3EpcId0 == endpointData.SrcInfo.L3EpcId) &&
		(epcInfo.L2EpcId1 == endpointData.DstInfo.L2EpcId) &&
		(epcInfo.L3EpcId1 == endpointData.DstInfo.L3EpcId)
}

// l2EpcId0=11,L3EpcId0=11,l2Epcid=0,L3EpcId0=0的数据正确性
func TestModifyEpcIdPolicy1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 11, 4)
	policy.UpdateInterfaceData([]*PlatformData{platformData1})
	generateIpgroupData(policy)
	generateAclData(policy)
	srcIp := NewIPFromString("192.168.0.11")
	dstIp := NewIPFromString("192.168.0.12")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfa,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeIPv4,
		DstPort: 8000,
		Ttl:     64,
		L2End0:  true,
		L2End1:  true,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	basicData := &EpcInfo{
		L2EpcId0: 11,
		L3EpcId0: 11,
		L2EpcId1: 0,
		L3EpcId1: 0,
	}
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}
}

// l2EpcId0=11,l3EpcId0=11,l2EpcId1=12,l3EpcId1=12的数据正确性
func TestModifyEpcIdPolicy2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 11, 4)
	platformData2 := generatePlatformDataByParam("192.168.0.12", "08:00:27:a4:2b:fd", 12, 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	srcIp := NewIPFromString("192.168.0.11")
	dstIp := NewIPFromString("192.168.0.12")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfc,
		DstMac:  0x80027a42bfd,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeIPv4,
		DstPort: 8000,
		Ttl:     64,
		L2End0:  true,
		L2End1:  true,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	basicData := &EpcInfo{
		L2EpcId0: 11,
		L3EpcId0: 11,
		L2EpcId1: 12,
		L3EpcId1: 12,
	}
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}
}

// l2EpcId0=-1,l3EpcId0=-1,l2Epcid1=0,l3EpcId1=12的数据正确性
func TestModifyEpcIdPolicy3(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 0, 3)
	platformData2 := generatePlatformDataByParam("192.168.0.12", "08:00:27:a4:2b:fd", 12, 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	srcIp := NewIPFromString("192.168.0.11")
	dstIp := NewIPFromString("192.168.0.12")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfa,
		DstMac:  0x80027a42bf0,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeIPv4,
		DstPort: 8000,
		Ttl:     64,
		L2End0:  true,
		L2End1:  true,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	basicData := &EpcInfo{
		L2EpcId0: -1,
		L3EpcId0: -1,
		L2EpcId1: 0,
		L3EpcId1: 12,
	}
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}
}

// l2EpcId0=11,l3EpcId0=11,l2EpcId1=0,l3EpcId1=-1的数据正确性
func TestModifyEpcIdPolicy4(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 11, 3)
	platformData2 := generatePlatformDataByParam("192.168.0.12", "08:00:27:a4:2b:fd", 0, 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	srcIp := NewIPFromString("192.168.0.11")
	dstIp := NewIPFromString("192.168.0.12")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfd,
		DstMac:  0x80027a42bf0,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeIPv4,
		DstPort: 8000,
		Ttl:     64,
		L2End0:  true,
		L2End1:  true,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	basicData := &EpcInfo{
		L2EpcId0: 11,
		L3EpcId0: 11,
		L2EpcId1: 0,
		L3EpcId1: -1,
	}
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}
}

// l3EpcId0=-1, l3EpcId1=-1的数据正确性
func TestModifyEpcIdPolicy5(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 0, 4)
	platformData2 := generatePlatformDataByParam("192.168.0.12", "08:00:27:a4:2b:fd", 0, 4)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	// l3EpcId0=-1, l3EpcId1=-1, l2EpcId0=0, l2EpcId1=0
	srcIp := NewIPFromString("192.168.0.11")
	dstIp := NewIPFromString("192.168.0.12")
	key := &LookupKey{
		SrcIp:   srcIp.Int(),
		SrcMac:  0x80027a42bfa,
		DstMac:  0x80027a42bfb,
		DstIp:   dstIp.Int(),
		EthType: EthernetTypeIPv4,
		DstPort: 8000,
		Ttl:     64,
		L2End0:  false,
		L2End1:  true,
		Proto:   6,
		Tap:     TAP_TOR,
	}
	basicData := &EpcInfo{
		L2EpcId0: 0,
		L3EpcId0: -1,
		L2EpcId1: 0,
		L3EpcId1: -1,
	}
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	// l3EpcId0=-1, l3EpcId1=-1, l2EpcId0=-1, l2EpcId1=-1
	key.SrcMac = 0x80027a42bfc
	key.DstMac = 0x80027a42bfd
	key.L2End0 = true
	basicData = &EpcInfo{
		L2EpcId0: -1,
		L3EpcId0: -1,
		L2EpcId1: -1,
		L3EpcId1: -1,
	}
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(basicData, data) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", data, "\n")
		t.Log("Expect:", basicData, "\n")
	}
}

// 以下是云平台信息和policy结合起来的测试
var (
	server = NewIPFromString("172.20.1.1").Int()

	group1Ip1  = NewIPFromString("192.168.1.10").Int()
	group1Mac  = NewMACAddrFromString("11:11:11:11:11:11").Int()
	group1Ip2  = NewIPFromString("192.168.1.20").Int()
	group1Mac2 = NewMACAddrFromString("11:11:11:11:11:12").Int()
	group1Ip3  = NewIPFromString("102.168.33.22").Int()
	group1Id   = uint32(10)

	group2Ip1 = NewIPFromString("10.30.1.10").Int()
	group2Mac = NewMACAddrFromString("22:22:22:22:22:22").Int()
	group2Ip2 = NewIPFromString("10.30.1.20").Int()
	group2Id  = uint32(20)

	group3Id = uint32(30)
	group4Id = uint32(40)
	group5Id = uint32(50)
	group6Id = uint32(60)
	group7Id = uint32(70)

	groupIp1 = NewIPFromString("192.168.10.10").Int()
	groupIp2 = NewIPFromString("192.168.10.123").Int()
	groupIp3 = NewIPFromString("192.168.20.112").Int()

	groupIp4 = NewIPFromString("172.16.1.200").Int()
	groupIp5 = NewIPFromString("172.16.2.100").Int()

	groupIp6 = NewIPFromString("10.33.1.10").Int()
	groupIp7 = NewIPFromString("10.30.122.3").Int()

	group3Mac1 = NewMACAddrFromString("33:33:33:33:33:31").Int()
	group4Mac1 = NewMACAddrFromString("44:44:44:44:44:41").Int()
	group5Mac1 = NewMACAddrFromString("55:55:55:55:55:51").Int()
	group5Mac2 = NewMACAddrFromString("55:55:55:55:55:52").Int()
	group6Mac1 = NewMACAddrFromString("66:66:66:66:66:61").Int()
	group7Mac1 = NewMACAddrFromString("66:66:66:66:66:62").Int()
)

func generatePlatformDataWithGroupId(epcId int32, groupId uint32, mac uint64) *PlatformData {
	data := PlatformData{
		EpcId:      epcId,
		DeviceType: 2,
		DeviceId:   3,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac,
		HostIp:     server,
	}
	data.GroupIds = append(data.GroupIds, groupId)
	return &data
}

func generatePolicyTable() *PolicyTable {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	datas := make([]*PlatformData, 0, 5)

	data1 := generatePlatformDataWithGroupId(int32(group1Id), group1Id, group1Mac)
	ip1 := generateIpNet(group1Ip1, 121, 24)
	ip2 := generateIpNet(group1Ip2, 121, 25)
	data1.Ips = append(data1.Ips, ip1, ip2)

	data2 := generatePlatformDataWithGroupId(int32(group1Id), 0, group1Mac2)
	ip1 = generateIpNet(group1Ip3, 121, 18)
	data2.Ips = append(data2.Ips, ip1)
	datas = append(datas, data1, data2)

	data1 = generatePlatformDataWithGroupId(int32(group2Id), group2Id, group2Mac)
	ip1 = generateIpNet(group2Ip1, 121, 24)
	ip2 = generateIpNet(group2Ip2, 121, 25)
	data1.Ips = append(data1.Ips, ip1, ip2)
	datas = append(datas, data1)

	// group3无epc，group4有epc  groupIp3 + groupIp4
	data1 = generatePlatformDataWithGroupId(0, group3Id, group3Mac1)
	ip1 = generateIpNet(groupIp3, 121, 24)
	ip2 = generateIpNet(groupIp4, 121, 32)
	data1.Ips = append(data1.Ips, ip1, ip2)
	datas = append(datas, data1)

	data1 = generatePlatformDataWithGroupId(int32(group4Id), group4Id, group4Mac1)
	ip1 = generateIpNet(groupIp3, 121, 24)
	ip2 = generateIpNet(groupIp4, 121, 32)
	data1.Ips = append(data1.Ips, ip1, ip2)
	datas = append(datas, data1)

	data1 = generatePlatformDataWithGroupId(0, group5Id, group5Mac1)
	ip1 = generateIpNet(groupIp5, 121, 24)
	ip2 = generateIpNet(groupIp6, 121, 32)
	data1.Ips = append(data1.Ips, ip1, ip2)

	data2 = generatePlatformDataWithGroupId(int32(group5Id), group5Id, group5Mac2)
	ip1 = generateIpNet(groupIp5, 121, 24)
	ip2 = generateIpNet(groupIp6, 121, 32)
	data2.Ips = append(data2.Ips, ip1, ip2)
	datas = append(datas, data1, data2)

	policy.UpdateInterfaceData(datas)

	ip3 := "192.168.10.10/24"  // 和groupIp1、groupIp2同网段
	ip4 := "192.168.20.112/32" // 和groupIp3同网段 -- group3Id
	ip5 := "10.25.1.2/24"
	ipgroups := make([]*IpGroupData, 0, 4)

	ipgroup1 := generateIpGroup(group3Id, 0, ip5)
	ipgroup2 := generateIpGroup(group5Id, 0, ip3)
	ipgroup3 := generateIpGroup(group6Id, 0, ip3)
	ipgroup3.Ips = append(ipgroup3.Ips, ip4)
	ipgroup4 := generateIpGroup(group7Id, 70, ip3)
	ipgroup4.Ips = append(ipgroup4.Ips, ip4)
	ipgroups = append(ipgroups, ipgroup1, ipgroup2, ipgroup3, ipgroup4)

	policy.UpdateIpGroupData(ipgroups)

	return policy
}

func generateAclAction(id ACLID, actionFlags ActionFlag) AclAction {
	return AclAction(id).AddActionFlags(actionFlags).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
}

func generatePolicyAcl(table *PolicyTable, action AclAction, aclID ACLID, srcGroupId, dstGroupId uint32,
	proto uint8, port uint16, vlan uint32) *Acl {
	srcGroups := make([]uint32, 0, 1)
	dstGroups := make([]uint32, 0, 1)
	dstPorts := make([]uint16, 0, 1)

	srcGroups = append(srcGroups, srcGroupId)
	dstGroups = append(dstGroups, dstGroupId)
	if port != 0 {
		dstPorts = append(dstPorts, port)
	}
	acl := &Acl{
		Id:        aclID,
		Type:      TAP_TOR,
		TapId:     uint32(aclID + 1),
		SrcGroups: srcGroups,
		DstGroups: dstGroups,
		DstPorts:  dstPorts,
		Proto:     proto,
		Vlan:      vlan,
		Action:    []AclAction{action},
	}
	return acl
}

func generateLookupKey(srcMac, dstMac uint64, vlan uint16, srcIp, dstIp uint32,
	proto uint8, srcPort, dstPort uint16) *LookupKey {
	key := &LookupKey{
		SrcMac:  srcMac,
		DstMac:  dstMac,
		SrcIp:   srcIp,
		DstIp:   dstIp,
		Proto:   proto,
		SrcPort: srcPort,
		DstPort: dstPort,
		Vlan:    vlan,
		Tap:     TAP_TOR,
	}
	return key
}

func TestPolicySimple(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action}, 10)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	// 构建查询key  2:8000->1:0 tcp
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 8000, 0)
	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, 10)
	// 查询结果和预期结果比较
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	// 构建无效查询key  2:0->1:8000 tcp
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// key不匹配，返回无效policy
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	// 测试同样的key, 匹配两条action
	action2 := generateAclAction(12, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl2)
	table.UpdateAcls(acls)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action, action2}, 10)

	key = generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

func TestPolicyEpcPolicy(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, 0, 6, 8000, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group1Mac2, 0, group1Ip1, group1Ip3, 6, 0, 8000)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action}, 10)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	backward := getBackwardAcl(action)
	key = generateLookupKey(group1Mac2, group1Mac, 0, group1Ip3, group1Ip1, 6, 8000, 0)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, 10)
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	key = generateLookupKey(group1Mac2, group1Mac, 0, group1Ip3, group1Ip1, 6, 0, 8000)
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	basicPolicyData = nil
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// 查询结果和预期结果比较
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
	}
}

func TestFlowVlanAcls(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable()
	action := generateAclAction(10, ACTION_FLOW_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 0, 10)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1->2 tcp vlan:10
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, 6, 11, 10)
	_, policyData := table.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward}, 10)
	key = generateLookupKey(group2Mac, group1Mac, 10, group2Ip1, group1Ip1, 6, 11, 10)
	_, policyData2 := table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData2, policyData2) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData2, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key不匹配，返回无效policy
	key = generateLookupKey(group2Mac, group1Mac, 11, group2Ip1, group1Ip1, 6, 11, 10)
	_, policyData3 := table.LookupAllByKey(key)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(basicPolicyData3, policyData3) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData3, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}
}

func TestIpGroupPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable()
	// group1->group2,tcp,vlan:10,dstport:20
	action := generateAclAction(10, ACTION_FLOW_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 20, 10)
	// group2->group1,tcp,vlan:10,dstport:21
	action2 := generateAclAction(12, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group2Id, group1Id, 6, 21, 10)
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)
	// 构建查询key  1:21->2:20 tcp vlan:10 ,匹配两条acl
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, 6, 21, 20)
	_, policyData := table.LookupAllByKey(key)
	backward := getBackwardAcl(action2)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action, backward}, 10)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

func TestVlanProtoPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable()
	// group1->group2, vlan:10
	action1 := generateAclAction(11, ACTION_FLOW_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 11, group1Id, group2Id, 0, 0, 10)
	// group1->group2, proto:6
	action2 := generateAclAction(12, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group1Id, group2Id, 6, 0, 0)
	// group1->group2, port:80
	action3 := generateAclAction(13, ACTION_FLOW_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 13, group1Id, group2Id, 0, 80, 0)
	acls = append(acls, acl1, acl2, acl3)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:10->2:10 proto:6 vlan:10
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, 6, 10, 10)
	// 获取first查询结果
	_, policyData := table.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action1, action2}, 11)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 2-key: 1:10 -> 2:80 proto:1 vlan:10
	key = generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, 1, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action1, action3}, 11)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 3-key: 1:10 -> 2:80 proto:6 vlan:0
	key = generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2, action3}, 12)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	acls = []*Acl{}
	table = generatePolicyTable()
	// port:80
	action4 := generateAclAction(14, ACTION_FLOW_COUNTING)
	acl4 := generatePolicyAcl(table, action4, 14, 0, 0, 0, 80, 0)
	// group1->group2, proto:6
	action5 := generateAclAction(15, ACTION_FLOW_COUNTING)
	acl5 := generatePolicyAcl(table, action5, 15, group1Id, group2Id, 6, 0, 0)
	acls = append(acls, acl4, acl5)
	table.UpdateAcls(acls)
	// 4-key  1:10->2:80 proto:6
	key = generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	backward1 := getBackwardAcl(action4)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action5, action4}, 15)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 5-key 2:80->1:10 proto:6
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 80, 10)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	backward2 := getBackwardAcl(action5)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward2, backward1}, 15)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("PortProto Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

func TestResourceGroupPolicy(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable()
	// acl1: dstGroup:group1
	// group1: epcId=10,mac=group1Mac,ips="group1Ip1/24,group1Ip2/25",subnetId=121
	action1 := generateAclAction(16, ACTION_FLOW_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 16, 0, group1Id, 0, 0, 0)
	acls = append(acls, acl1)
	table.UpdateAcls(acls)
	// 构建查询1-key  (group1)group1Ip1:10->(group1)group1Ip2:10 proto:6 vlan:10
	key := generateLookupKey(group1Mac, group1Mac, 10, group1Ip1, group1Ip2, 6, 10, 10)
	_, policyData := table.LookupAllByKey(key)
	backward := getBackwardAcl(action1)
	// 可匹配acl1，direction=3
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action1, backward}, 16)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	acls = []*Acl{}
	table = generatePolicyTable()
	// acl2: dstGroup:group5
	// acl3: srcGroup:group3-> dstGroup:group5,dstPort=1023,udp
	// group5: 1.epcId=0,mac=group5Mac1,ips="groupIp5/24,groupIp6/32"
	//         2.epcId=50,mac=group5Mac2,ips="groupIp5/24,groupIp6/32"
	action2 := generateAclAction(18, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 18, 0, group5Id, 0, 0, 0)
	action3 := generateAclAction(19, ACTION_FLOW_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 19, group3Id, group5Id, 17, 1023, 0)
	acls = append(acls, acl2, acl3)
	table.UpdateAcls(acls)
	// 2-key  (group5)groupIp5:1000->(group5)groupIp6:1023 udp
	key = generateLookupKey(group5Mac1, group5Mac1, 0, groupIp5, groupIp6, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	backward = getBackwardAcl(action2)
	// 匹配action2及backward，但不匹配action3
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2, backward}, 18)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 3-key  非资源组ip->(group5)groupIp5  3和4都可匹配action2
	ip1 := NewIPFromString("1.1.1.1").Int()
	key = generateLookupKey(0, group5Mac1, 0, ip1, groupIp5, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2}, 18)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 4-key 非资源组ip->(group5)groupIp6
	key = generateLookupKey(0, group5Mac1, 0, ip1, groupIp6, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2}, 18)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 4-key Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 4-key FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	// 5-key (group3)groupIp3网段云外ip2:1000 -> (group5)groupIp5网段云外ip3:1023 udp
	ip2 := NewIPFromString("10.25.1.10").Int()
	ip3 := NewIPFromString("192.168.10.10").Int()
	key = generateLookupKey(group3Mac1, group5Mac1, 0, ip2, ip3, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action3, action2}, 19)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 5-key Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 5-key FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}

	// 6-key group3Mac1 + ip:1000 -> (group5)groupIp5:1023 udp,vlan:10
	//      (group3)mac和ip不对应情况下，虽能匹配到group3Id，但三层epcId=-1
	ip := NewIPFromString("10.25.2.2").Int()
	key = generateLookupKey(group3Mac1, group5Mac2, 10, ip, groupIp5, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action3, action2}, 19)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData, "\n")
	}
}

func TestSrcDevGroupDstIpGroupPolicy(t *testing.T) {
	table := generatePolicyTable()
	acls := []*Acl{}
	// acl1: dstGroup: group6(IP资源组)，udp
	// acl2: srcGroup: group3(DEV资源组)，udp
	action1 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 20, 0, group6Id, 17, 0, 0)
	action2 := generateAclAction(21, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 21, group3Id, 0, 17, 0, 0)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group3/group6)groupIp3 -> (group6)groupIp2 udp
	key1 := generateLookupKey(group3Mac1, group6Mac1, 0, groupIp3, groupIp2, 17, 0, 0)
	result := table.cloudPlatformLabeler.GetEndpointData(key1)
	policyData := table.policyLabeler.GetPolicyByFirstPath(result, key1)
	backward1 := getBackwardAcl(action1)
	basicPolicyData1 := NewPolicyData()
	basicPolicyData1.Merge([]AclAction{action2, action1, backward1}, 21) // 可以匹配backward1
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2: (group3)groupIp4 -> (group3/group6)groupIp3
	key2 := generateLookupKey(group3Mac1, group6Mac1, 0, groupIp4, groupIp3, 17, 0, 0)
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	// 不匹配backward2
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{action2, action1}, 21)
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key1 - FastPath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2 - FastPath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// acl3: dstGroup: group7(IP资源组)： 和group6所含IP相同，但有epc限制 udp
	// acl4: srcGroup: group4(DEV资源组): 和group3所含IP相同，但有epc限制 udp
	action3 := generateAclAction(22, ACTION_PACKET_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 22, 0, group7Id, 17, 0, 0)
	action4 := generateAclAction(23, ACTION_PACKET_COUNTING)
	acl4 := generatePolicyAcl(table, action4, 23, group4Id, 0, 17, 0, 0)
	acls = append(acls, acl3, acl4)
	table.UpdateAcls(acls)

	// key3: (group3)groupIp4:8000 -> (group5/group6)groupIp2:6000 udp vlan:10
	key3 := generateLookupKey(group3Mac1, 0, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key3)
	// 匹配group6、group3，group7有epc限制，group4mac不符
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key3)
	basicPolicyData3 := NewPolicyData()
	basicPolicyData3.Merge([]AclAction{action2, action1}, 21)
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4: (group4)groupIp4:8000 -> (group5/group6)groupIp2:6000 udp
	key4 := generateLookupKey(group4Mac1, group5Mac1, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	// 源端匹配group4不匹配group3，目的端匹配group6不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	basicPolicyData4 := NewPolicyData()
	basicPolicyData4.Merge([]AclAction{action4, action1}, 23)
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}

	// key5: (group4)group4Id:8000 -> (group5/group6)groupIp2:6000 udp
	key5 := generateLookupKey(group4Mac1, 0, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key5)
	// 源端匹配group4不匹配group3,目的端匹配group6不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key5)
	basicPolicyData5 := NewPolicyData()
	basicPolicyData5.Merge([]AclAction{action4, action1}, 23)
	if !CheckPolicyResult(basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData5, "\n")
	}

	// (mac、ip不匹配) groupIp4 :8000 -> (group6)groupIp2:6000 udp
	key6 := generateLookupKey(group5Mac2, group7Mac1, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key6)
	// 源端不匹配group3/group4,目的端匹配group6，不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key6)
	basicPolicyData6 := NewPolicyData()
	basicPolicyData6.Merge([]AclAction{action1}, 20)
	if !CheckPolicyResult(basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData6, "\n")
	}

	// key3 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}

	// key5 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key5)
	if !CheckPolicyResult(basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData5, "\n")
	}

	// key6 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key6)
	if !CheckPolicyResult(basicPolicyData6, policyData) {
		t.Error("key6 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData6, "\n")
	}

}

func TestFirstPathVsFastPath(t *testing.T) {
	table := generatePolicyTable()
	acls := []*Acl{}
	// acl1: srcGroup: group5, dstPort:8000 tcp
	// acl2: srcGroup: group5, vlan:10
	action1 := generateAclAction(24, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 24, group5Id, 0, 6, 8000, 0)
	action2 := generateAclAction(25, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 25, group5Id, 0, 0, 0, 10)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group5)groupIp5:6000 -> (group5/group6)groupIp2:8000 tcp vlan:10
	key1 := generateLookupKey(group5Mac1, group6Mac1, 10, groupIp5, groupIp2, 6, 6000, 8000)
	result := table.cloudPlatformLabeler.GetEndpointData(key1)
	policyData := table.policyLabeler.GetPolicyByFirstPath(result, key1)
	// 可匹配acl1，direction=3; 可匹配acl2，direction=1
	backward1 := getBackwardAcl(action1)
	backward2 := getBackwardAcl(action2)
	basicPolicyData1 := NewPolicyData()
	basicPolicyData1.Merge([]AclAction{action2, backward2, action1}, 25)
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2:(group6)groupIp3:6000 -> (group5)groupIp5:8000 tcp vlan:10
	key2 := generateLookupKey(group6Mac1, group5Mac1, 10, groupIp3, groupIp5, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	// 不能匹配acl1
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward2}, 25)
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key3: (group5)groupIp6:8000 -> (group5)groupIp5:8000 tcp
	key3 := generateLookupKey(group5Mac2, group5Mac1, 10, groupIp6, groupIp5, 6, 8000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key3)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key3)
	// 可匹配acl1，direction=3；可匹配acl2，direction=3
	basicPolicyData3 := NewPolicyData()
	basicPolicyData3.Merge([]AclAction{action2, action1, backward2, backward1}, 25)
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4: (group5)groupIp6:6000 -> (group6)groupIp3:8000 tcp vlan:11
	key4 := generateLookupKey(group5Mac1, group6Mac1, 11, groupIp6, groupIp3, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	// 不可匹配acl2，vlan不符
	basicPolicyData4 := NewPolicyData()
	basicPolicyData4.Merge([]AclAction{action1}, 24)
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}

	// key5: (group5)groupIp5:6000 -> (group6)groupIp3:8000 udp vlan:10
	key5 := generateLookupKey(group5Mac1, group6Mac1, 10, groupIp5, groupIp3, 17, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key5)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key5)
	// udp协议，不匹配acl1
	basicPolicyData5 := NewPolicyData()
	basicPolicyData5.Merge([]AclAction{action2}, 25)
	if !CheckPolicyResult(basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData5, "\n")
	}

	// key6: (group5)groupIp5:6000 -> (group6)groupIp3:6000
	key6 := generateLookupKey(group5Mac1, group6Mac1, 10, groupIp5, groupIp3, 6, 6000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key6)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key6)
	// port不一致，不匹配acl1
	basicPolicyData6 := NewPolicyData()
	basicPolicyData6.Merge([]AclAction{action2}, 25)
	if !CheckPolicyResult(basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData6, "\n")
	}

	// key7: (group5)groupIp5:6000 -> (group6)groupIp3:8000 vlan:11 tcp
	key7 := generateLookupKey(group5Mac1, group6Mac1, 11, groupIp5, groupIp3, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key7)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key7)
	// 不匹配acl2，vlan不符
	basicPolicyData7 := NewPolicyData()
	basicPolicyData7.Merge([]AclAction{action1}, 24)
	if !CheckPolicyResult(basicPolicyData7, policyData) {
		t.Error("key7 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData7, "\n")
	}

	// key1 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key3 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}

	// key5 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key5)
	if !CheckPolicyResult(basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData5, "\n")
	}

	// key6 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key6)
	if !CheckPolicyResult(basicPolicyData6, policyData) {
		t.Error("key6 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData6, "\n")
	}

	// key7 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key7)
	if !CheckPolicyResult(basicPolicyData7, policyData) {
		t.Error("key7 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData7, "\n")
	}
}

func TestEndpointDataDirection(t *testing.T) {
	table := generatePolicyTable()
	acls := []*Acl{}
	// acl1: dstGroup:group4, dstPort:1000 tcp
	// acl2: srcGroup:group3, dstPort:1000 tcp
	action1 := generateAclAction(25, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 25, 0, group4Id, 6, 1000, 0)
	action2 := generateAclAction(26, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 26, group3Id, 0, 6, 1000, 0)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group3/group6)groupIp3:1023 -> (group4)groupIp4:1000 tcp
	key1 := generateLookupKey(group3Mac1, group4Mac1, 0, groupIp3, groupIp4, 6, 1023, 1000)
	// src: DEV-30, IP-60 dst: DEV-40
	result := table.cloudPlatformLabeler.GetEndpointData(key1)
	basicSrcInfo1 := table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	basicDstInfo1 := table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	if !CheckEndpointDataResult(basicSrcInfo1, basicDstInfo1, result) {
		t.Error("key1 EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo1, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo1, "\n")
	}
	policyData := table.policyLabeler.GetPolicyByFirstPath(result, key1)
	basicPolicyData1 := NewPolicyData()
	basicPolicyData1.Merge([]AclAction{action2, action1}, 26)
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2: (group4)groupIp4:1000 -> (group3/group6)groupIp3:1023 tcp
	key2 := generateLookupKey(group4Mac1, group3Mac1, 0, groupIp4, groupIp3, 6, 1000, 1023)
	// src: DEV-40 dst: DEV-30, IP-60
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	basicSrcInfo2 := table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	basicDstInfo2 := table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	if !CheckEndpointDataResult(basicSrcInfo2, basicDstInfo2, result) {
		t.Error("key2 EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo2, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo2, "\n")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	backward1 := getBackwardAcl(action1)
	backward2 := getBackwardAcl(action2)
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward2, backward1}, 26)
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key3: (group3/group6)groupIp3:1000 -> (group4)groupIp4:1023 tcp
	key3 := generateLookupKey(group3Mac1, group4Mac1, 0, groupIp3, groupIp4, 6, 1000, 1023)
	// src: DEV-30, IP-60 dst: DEV-40
	result = table.cloudPlatformLabeler.GetEndpointData(key3)
	basicSrcInfo3 := table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	basicDstInfo3 := table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	if !CheckEndpointDataResult(basicSrcInfo3, basicDstInfo3, result) {
		t.Error("key3 EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo3, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo3, "\n")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key3)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4: (group4)groupIp4:1023 -> (group3/group6)groupIp3:1000 tcp
	key4 := generateLookupKey(group4Mac1, group3Mac1, 0, groupIp4, groupIp3, 6, 1023, 1000)
	// src: DEV-40 dst: DEV-30, IP-60
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	basicSrcInfo4 := table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	basicDstInfo4 := table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	if !CheckEndpointDataResult(basicSrcInfo4, basicDstInfo4, result) {
		t.Error("key4 EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo4, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo4, "\n")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	basicPolicyData4 := INVALID_POLICY_DATA
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}

	// key1 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckEndpointDataResult(basicSrcInfo1, basicDstInfo1, result) {
		t.Error("key1 FastPath EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo1, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo1, "\n")
	}
	if !CheckPolicyResult(basicPolicyData1, policyData) {
		t.Error("FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData1, "\n")
	}

	// key2 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckEndpointDataResult(basicSrcInfo2, basicDstInfo2, result) {
		t.Error("key2 FastPath EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo2, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo2, "\n")
	}
	if !CheckPolicyResult(basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData2, "\n")
	}

	// key3 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckEndpointDataResult(basicSrcInfo3, basicDstInfo3, result) {
		t.Error("key3 FastPath EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo3, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo3, "\n")
	}
	if !CheckPolicyResult(basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData3, "\n")
	}

	// key4 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckEndpointDataResult(basicSrcInfo4, basicDstInfo4, result) {
		t.Error("key4 FastPath EndpointData Check Failed")
		t.Log("ResultSrcInfo:", result.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicSrcInfo4, "\n")
		t.Log("ResultDstInfo:", result.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicDstInfo4, "\n")
	}
	if !CheckPolicyResult(basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed")
		t.Log("Result:", policyData, "\n")
		t.Log("Expect:", basicPolicyData4, "\n")
	}
}
