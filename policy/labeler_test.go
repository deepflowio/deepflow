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
	ttl           = uint8(64)
	ip1           = NewIPFromString("192.168.2.12").Int()
	ip2           = NewIPFromString("192.168.2.0").Int()
	ip3           = NewIPFromString("192.168.0.11").Int()
	ip4           = NewIPFromString("192.168.0.12").Int()
	mac1          = NewMACAddrFromString("08:00:27:a4:2b:f0").Int()
	mac2          = NewMACAddrFromString("08:00:27:a4:2b:fa").Int()
	mac3          = NewMACAddrFromString("08:00:27:a4:2b:fb").Int()
	mac4          = NewMACAddrFromString("08:00:27:a4:2b:fc").Int()
	mac5          = NewMACAddrFromString("08:00:27:a4:2b:fd").Int()
	launchServer1 = NewIPFromString("10.10.10.10").Int()
	datas         = make([]*PlatformData, 0, 2)
	ipGroups      = make([]*IpGroupData, 0, 3)
)

// 和云平台结合起来的测试例所需常量定义
var (
	server = NewIPFromString("172.20.1.1").Int()

	group1Id = uint32(10)
	group2Id = uint32(20)
	group3Id = uint32(30)
	group4Id = uint32(40)
	group5Id = uint32(50)
	group6Id = uint32(60)
	group7Id = uint32(70)

	group1Ip1  = NewIPFromString("192.168.1.10").Int()
	group1Mac  = NewMACAddrFromString("11:11:11:11:11:11").Int()
	group1Ip2  = NewIPFromString("192.168.1.20").Int()
	group1Mac2 = NewMACAddrFromString("11:11:11:11:11:12").Int()
	group1Ip3  = NewIPFromString("102.168.33.22").Int()

	group2Ip1 = NewIPFromString("10.30.1.10").Int()
	group2Mac = NewMACAddrFromString("22:22:22:22:22:22").Int()
	group2Ip2 = NewIPFromString("10.30.1.20").Int()

	ipNet1 = "192.168.10.10/24"  // 和groupIp1、groupIp2同网段
	ipNet2 = "192.168.20.112/32" // 和groupIp3同网段 -- group3Id
	ipNet3 = "10.25.1.2/24"

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

type EndInfo struct {
	L2End0 bool
	L3End0 bool
	L2End1 bool
	L3End1 bool
}

type EpcInfo struct {
	L2EpcId0 int32
	L3EpcId0 int32
	L2EpcId1 int32
	L3EpcId1 int32
}

func generateEpcInfo(l2EpcId0, l3EpcId0, l2EpcId1, l3EpcId1 int32) *EpcInfo {
	basicData := &EpcInfo{
		L2EpcId0: l2EpcId0,
		L3EpcId0: l3EpcId0,
		L2EpcId1: l2EpcId1,
		L3EpcId1: l3EpcId1,
	}
	return basicData
}

func generateEndInfo(l2End0, l3End0, l2End1, l3End1 bool) *EndInfo {
	basicEnd := &EndInfo{
		L2End0: l2End0,
		L3End0: l3End0,
		L2End1: l2End1,
		L3End1: l3End1,
	}
	return basicEnd
}

func generateIpNet(ip uint32, subnetId uint32, mask uint32) *IpNet {
	ipInfo := IpNet{
		Ip:       ip,
		SubnetId: subnetId,
		Netmask:  mask,
	}
	return &ipInfo
}

func generateIpGroup(groupId uint32, epcId int32, ip ...string) *IpGroupData {
	ipGroup := IpGroupData{
		Id:    groupId,
		EpcId: epcId,
	}
	ipGroup.Ips = append(ipGroup.Ips, ip...)
	return &ipGroup
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

func generatePlatformDataByParam(strIp, StrMac string, epcId int32, Iftype uint32) *PlatformData {
	ip := NewIPFromString(strIp)
	ipInfo := generateIpNet(ip.Int(), 121, 32)

	mac := NewMACAddrFromString(StrMac).Int()
	vifData := generatePlatformDataExtension(epcId, 1, 3, Iftype, 5, mac, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo)
	return vifData
}

func generatePlatformDataWithGroupId(epcId int32, groupId uint32, mac uint64, ips ...*IpNet) *PlatformData {
	data := PlatformData{
		EpcId:      epcId,
		DeviceType: 2,
		DeviceId:   3,
		IfType:     3,
		IfIndex:    5,
		Mac:        mac,
		HostIp:     server,
	}
	data.Ips = append(data.Ips, ips...)
	data.GroupIds = append(data.GroupIds, groupId)
	return &data
}

func generateAclAction(id ACLID, actionFlags ActionFlag) AclAction {
	return AclAction(id).AddActionFlags(actionFlags).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
}

func getBackwardAcl(acl AclAction) AclAction {
	return acl.SetDirections(BACKWARD)
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

// 设置key的其他参数
func setEthTypeAndOthers(key *LookupKey, ethType EthernetType, ttl uint8, l2End0, l2End1 bool) *LookupKey {
	key.EthType = ethType
	key.Ttl = ttl
	key.L2End0 = l2End0
	key.L2End1 = l2End1
	return key
}

func generateClassicLookupKey(srcMac, dstMac uint64, srcIp, dstIp uint32,
	srcPort, dstPort uint16, ethType EthernetType) *LookupKey {
	key := &LookupKey{
		SrcMac:  srcMac,
		DstMac:  dstMac,
		SrcIp:   srcIp,
		DstIp:   dstIp,
		SrcPort: srcPort,
		DstPort: dstPort,
		EthType: ethType,
		Ttl:     ttl,
		Tap:     TAP_TOR,
	}
	return key
}

func (policy *PolicyTable) UpdateAcls(acl []*Acl) {
	policy.UpdateAclData(acl)
	policy.EnableAclData()
}

// 生成特定IP资源组信息
func generateIpgroupData(policy *PolicyTable) {
	ipGroup1 := generateIpGroup(2, 11, "192.168.0.11/24")
	ipGroup2 := generateIpGroup(3, 11, "192.168.0.11/24")
	ipGroup3 := generateIpGroup(4, 12, "192.168.0.11/24")

	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3)
	policy.UpdateIpGroupData(ipGroups)
}

// 生成特定平台信息
func generatePlatformData(policy *PolicyTable) {
	ipInfo := generateIpNet(ip3, 121, 32)
	// ecpId:11 DeviceType:1 DeviceId:3 IfType:4 IfIndex:5 Mac:mac4 HostIp:launchServer1
	vifData := generatePlatformDataExtension(11, 1, 3, 4, 5, mac4, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo)
	datas = append(datas, vifData)

	policy.UpdateInterfaceData(datas)
}

// 生成特定平台和资源组信息
func generatePolicyTable() *PolicyTable {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	ip1 := generateIpNet(group1Ip1, 121, 24)
	ip2 := generateIpNet(group1Ip2, 121, 25)
	data1 := generatePlatformDataWithGroupId(int32(group1Id), group1Id, group1Mac, ip1, ip2)

	ip1 = generateIpNet(group1Ip3, 121, 18)
	data2 := generatePlatformDataWithGroupId(int32(group1Id), 0, group1Mac2, ip1)

	ip1 = generateIpNet(group2Ip1, 121, 24)
	ip2 = generateIpNet(group2Ip2, 121, 25)
	data3 := generatePlatformDataWithGroupId(int32(group2Id), group2Id, group2Mac, ip1, ip2)

	// group3无epc，group4有epc  groupIp3 + groupIp4
	ip1 = generateIpNet(groupIp3, 121, 24)
	ip2 = generateIpNet(groupIp4, 121, 32)
	data4 := generatePlatformDataWithGroupId(0, group3Id, group3Mac1, ip1, ip2)
	datas = append(datas, data1, data2, data3, data4)

	ip1 = generateIpNet(groupIp3, 121, 24)
	ip2 = generateIpNet(groupIp4, 121, 32)
	data1 = generatePlatformDataWithGroupId(int32(group4Id), group4Id, group4Mac1, ip1, ip2)

	ip1 = generateIpNet(groupIp5, 121, 24)
	ip2 = generateIpNet(groupIp6, 121, 32)
	data2 = generatePlatformDataWithGroupId(0, group5Id, group5Mac1, ip1, ip2)

	ip1 = generateIpNet(groupIp5, 121, 24)
	ip2 = generateIpNet(groupIp6, 121, 32)
	data3 = generatePlatformDataWithGroupId(int32(group5Id), group5Id, group5Mac2, ip1, ip2)
	datas = append(datas, data1, data2, data3)

	policy.UpdateInterfaceData(datas)

	ipGroup1 := generateIpGroup(group3Id, 0, ipNet3)
	ipGroup2 := generateIpGroup(group5Id, 0, ipNet1)
	ipGroup3 := generateIpGroup(group6Id, 0, ipNet1, ipNet2)
	ipGroup4 := generateIpGroup(group7Id, 70, ipNet1, ipNet2)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3, ipGroup4)

	policy.UpdateIpGroupData(ipGroups)

	return policy
}

// 生成特定Acl规则
func generateAclData(policy *PolicyTable) {
	dstPorts := []uint16{8000}
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, uint8(IPProtocolTCP), dstPorts[0], 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, uint8(IPProtocolTCP), 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})
}

func CheckPolicyResult(t *testing.T, basicPolicy *PolicyData, targetPolicy *PolicyData) bool {
	if !reflect.DeepEqual(basicPolicy, targetPolicy) {
		t.Log("Result:", targetPolicy, "\n")
		t.Log("Expect:", basicPolicy, "\n")
		return false
	} else {
		return true
	}
}

func CheckEpcTestResult(t *testing.T, basicEpcInfo *EpcInfo, targetEndpointData *EndpointData) bool {
	if !((basicEpcInfo.L2EpcId0 == targetEndpointData.SrcInfo.L2EpcId) &&
		(basicEpcInfo.L3EpcId0 == targetEndpointData.SrcInfo.L3EpcId) &&
		(basicEpcInfo.L2EpcId1 == targetEndpointData.DstInfo.L2EpcId) &&
		(basicEpcInfo.L3EpcId1 == targetEndpointData.DstInfo.L3EpcId)) {
		t.Log("Result:", targetEndpointData, "\n")
		t.Log("Expect:", basicEpcInfo, "\n")
		return false
	} else {
		return true
	}
}

func CheckEndpointDataResult(t *testing.T, basicEndpointData *EndpointData, targetEndpointData *EndpointData) bool {
	if !(reflect.DeepEqual(basicEndpointData.SrcInfo, targetEndpointData.SrcInfo) &&
		reflect.DeepEqual(basicEndpointData.DstInfo, targetEndpointData.DstInfo)) {
		t.Log("ResultSrcInfo:", targetEndpointData.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicEndpointData.SrcInfo, "\n")
		t.Log("ResultDstInfo:", targetEndpointData.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicEndpointData.DstInfo, "\n")
		return false
	} else {
		return true
	}
}

// 平台信息有关测试
func TestGetPlatformData(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// ecpId:11 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac4 HostIp:launchServer1
	vifData := generatePlatformDataExtension(11, 2, 3, 3, 5, mac4, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	ipInfo2 := generateIpNet(ip2, 125, 24)
	ipInfo3 := generateIpNet(ip1, 126, 32)
	vifData1 := generatePlatformDataExtension(0, 1, 100, 3, 5, mac2, launchServer1)
	vifData1.Ips = append(vifData1.Ips, ipInfo2, ipInfo3)

	datas = append(datas, vifData, vifData1)
	policy.UpdateInterfaceData(datas)

	key := generateLookupKey(mac4, mac2, 0, ip1, ip3, 0, 0, 0)
	result, _ := policy.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
}

func TestGetPlatformDataAboutArp(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// ecpId:11 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac4 HostIp:launchServer1
	vifData := generatePlatformDataExtension(11, 2, 3, 3, 5, mac4, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	datas = append(datas, vifData)
	policy.UpdateInterfaceData(datas)

	key := generateClassicLookupKey(mac4, mac2, ip1, ip3, 0, 0, EthernetTypeARP)
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
	policy.UpdateAcls(nil)

	key := generateClassicLookupKey(mac4, mac2, ip3, ip4, 0, 0, EthernetTypeARP)
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

	key := generateClassicLookupKey(mac4, mac2, ip3, ip4, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAllPassPolicy Check failed!")
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

	key := generateClassicLookupKey(mac4, mac2, ip3, ip4, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestGroupForwardPassPolicy Check Failed!")
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

	key := generateClassicLookupKey(mac4, mac2, ip3, ip4, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestGroupBackwardPassPolicy Check Failed!")
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

	key := generateClassicLookupKey(mac4, mac2, ip3, ip4, 30, 30, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAllPortPassPolicy Check Failed!")
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

	key := generateLookupKey(mac4, mac2, 0, ip3, ip4, uint8(IPProtocolTCP), 30, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestSrcPortPassPolicy Check Failed!")
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

	key := generateLookupKey(mac4, mac2, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDstPortPassPolicy Check Failed!")
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

	key := generateLookupKey(mac4, mac2, 0, ip3, ip4, uint8(IPProtocolTCP), 30, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestSrcDstPortPassPolicy Check Failed!")
	}
}

//测试Vlan策略匹配 acl配置Vlan=30，查询Vlan=30, 查询到Acl
func TestVlanPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	acl1 := generatePolicyAcl(policy, forward, 10, 0, 0, 0, 0, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, 30, ip3, ip4, uint8(IPProtocolTCP), 30, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPassPolicy Check Failed!")
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

	key := generateLookupKey(mac4, mac2, 30, ip3, ip4, uint8(IPProtocolTCP), 8000, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortPassPolicy Check Failed!")
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

	key := generateLookupKey(mac4, mac2, 30, ip3, ip4, uint8(IPProtocolTCP), 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPortProtoPassPolicy Check Failed!")
	}
}

//测试两条acl proto为6和17 查询proto=6的acl,proto为6的匹配成功
func TestAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 17, 8000, 0)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 30, ip3, ip4, uint8(IPProtocolTCP), 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)

	backward1 := getBackwardAcl(aclAction1)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction1, backward1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclsPassPolicy Check Failed!")
	}
}

//测试两条acl vlan为10和0  查询vlan=10的策略，结果两条都能匹配
func TestVlanAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 8000
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 8000, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip3, ip4, uint8(IPProtocolTCP), 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)

	backward1 := getBackwardAcl(aclAction1)
	backward2 := getBackwardAcl(aclAction2)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, aclAction1, backward2, backward1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanAclsPassPolicy Check Failed!")
	}
}

//测试两条acl vlan=10和port=8000  查询vlan=10,port=1000，匹配到vlan=10的策略
func TestVlanPortAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip3, ip4, uint8(IPProtocolTCP), 0, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	backward := getBackwardAcl(aclAction2)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, backward}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy Check Failed!")
	}
}

//测试两条acl vlan=10和port=8000  查询vlan=10,port=8000，两条策略都匹配到
func TestVlanPortAclsPassPolicy1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 8000
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	acl2Backward := getBackwardAcl(aclAction2)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction2, acl2Backward, aclAction1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy1 Check Failed!")
	}
}

//测试两条acl vlan=10和port=8000  查询port=8000，匹配到port=8000的策略
func TestVlanPortAclsPassPolicy2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, 0, 0, 6, 8000, 0)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, 0, 0, 6, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, false)

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{aclAction1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy2 Check Failed!")
	}

	_, policyData = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy2 FastPath Check Failed!")
	}
}

// l2EpcId0=11,L3EpcId0=11,l2Epcid=0,L3EpcId0=0的数据正确性
func TestModifyEpcIdPolicy1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fc", 11, 4)
	policy.UpdateInterfaceData([]*PlatformData{platformData1})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac4, mac2, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, true, true)

	basicData := generateEpcInfo(11, 11, 0, 0)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy1 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy1 FastPath Check Failed!")
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

	key := generateLookupKey(mac4, mac5, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, true, true)

	basicData := generateEpcInfo(11, 11, 12, 12)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 FastPath Check Failed!")
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

	key := generateLookupKey(mac2, mac1, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, true, true)

	basicData := generateEpcInfo(-1, -1, 0, 12)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 FastPath Check Failed!")
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

	key := generateLookupKey(mac5, mac1, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, true, true)

	basicData := generateEpcInfo(11, 11, 0, -1)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy4 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy4 FastPath Check Failed!")
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

	key := generateLookupKey(mac2, mac3, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, false, true)

	basicData := generateEpcInfo(0, -1, 0, -1)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 FastPath Check Failed!")
	}

	// l3EpcId0=-1, l3EpcId1=-1, l2EpcId0=-1, l2EpcId1=-1
	key.SrcMac = mac4
	key.DstMac = mac5
	key.L2End0 = true

	basicData = generateEpcInfo(-1, -1, -1, -1)
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5-2 Check Failed!")
	}

	data, _ = policy.policyLabeler.GetPolicyByFastPath(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5-2 FastPath Check Failed!")
	}
}

func checkEndTestResult(t *testing.T, basicEndInfo *EndInfo, targetEndpointData *EndpointData) bool {
	if (basicEndInfo.L2End0 == targetEndpointData.SrcInfo.L2End) &&
		(basicEndInfo.L3End0 == targetEndpointData.SrcInfo.L3End) &&
		(basicEndInfo.L2End1 == targetEndpointData.DstInfo.L2End) &&
		(basicEndInfo.L3End1 == targetEndpointData.DstInfo.L3End) {
		return true
	}

	t.Log("Result:", targetEndpointData, "\n")
	t.Log("Expect:", basicEndInfo, "\n")
	return false
}

// L2end0=L2end1=false L3end0=L3end1=false
func TestL2endL3end1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, false, false)

	basicEndInfo := generateEndInfo(false, false, false, false)
	data := policy.cloudPlatformLabeler.GetEndpointData(key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end1 Check Failed!")
	}
}

// L2end0=L2end1=true L3end0=L3end1=false
func TestL2endL3end2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, true, true)

	basicEndInfo := generateEndInfo(true, false, true, false)
	data := policy.cloudPlatformLabeler.GetEndpointData(key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end2 Check Failed!")
	}
}

// L2end0=L2end1=false L3end0=true,L3end01=false
func TestL2endL3end3(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, false)

	basicEndInfo := generateEndInfo(false, true, false, false)
	data := policy.cloudPlatformLabeler.GetEndpointData(key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end3 Check Failed!")
	}
}

// L2endn=L2end1=true L3end0=true, L3end1=false
func TestL2endL3end4(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)

	basicEndInfo := generateEndInfo(true, true, true, false)
	data := policy.cloudPlatformLabeler.GetEndpointData(key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end4 Check Failed!")
	}
}

// arp包 ip3-->ip4 ttl=64  L2end=L2end1=false L3end0=true,L3end1=false
// ip包  ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=false,L3end1=true
// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=false
// arp包 ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
func TestL2endL3end5(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	// arp包 ip3-->ip4 ttl=64  L2end=L2end1=false L3end0=true,L3end1=false
	key1 := generateLookupKey(mac3, mac4, 0, ip3, ip4, 0, 0, 8000)
	setEthTypeAndOthers(key1, EthernetTypeARP, 64, false, false)
	data := policy.cloudPlatformLabeler.GetEndpointData(key1)
	basicEndInfo := generateEndInfo(false, true, false, false)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key2 := generateLookupKey(mac4, mac3, 0, ip4, ip3, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, false, false)
	basicEndInfo = generateEndInfo(false, true, false, true)
	data = policy.cloudPlatformLabeler.GetEndpointData(key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=false,L3end1=true
	key2.Ttl = 63
	basicEndInfo.L3End0 = false
	data = policy.cloudPlatformLabeler.GetEndpointData(key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=false
	key3 := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 63, false, false)
	data = policy.cloudPlatformLabeler.GetEndpointData(key3)
	basicEndInfo = generateEndInfo(false, true, false, false)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// arp包 ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key4 := generateLookupKey(mac4, mac3, 0, ip4, ip3, 0, 0, 8000)
	setEthTypeAndOthers(key4, EthernetTypeARP, 64, false, false)
	basicEndInfo = generateEndInfo(false, true, false, true)
	data = policy.cloudPlatformLabeler.GetEndpointData(key4)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
	data = policy.cloudPlatformLabeler.GetEndpointData(key3)
	basicEndInfo = generateEndInfo(false, true, false, true)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}
}

func BenchmarkGetEndpointData(b *testing.B) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam("192.168.0.11", "08:00:27:a4:2b:fa", 11, 4)
	platformData1.GroupIds = append(platformData1.GroupIds, 2)
	platformData2 := generatePlatformDataByParam("192.168.0.12", "08:00:27:a4:2b:fb", 20, 4)
	platformData2.GroupIds = append(platformData2.GroupIds, 40)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	key := generateLookupKey(mac2, mac3, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, true, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.cloudPlatformLabeler.GetEndpointData(key)
	}
}

// 以下是云平台信息和policy结合起来的测试
func TestPolicySimple(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := NewPolicyData()
	basicPolicyData.Merge([]AclAction{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple Check Failed!")
	}

	// 构建查询2-key  2:8000->1:0 tcp
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 8000, 0)
	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, acl.Id)
	// 查询结果和预期结果比较
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple 2-key Check Failed!")
	}

	// 构建无效查询3-key  2:0->1:8000 tcp
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// key不匹配，返回无效policy
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple 3-key Check Failed!")
	}

	// 测试同样的key, 匹配两条action
	action2 := generateAclAction(12, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl2)
	table.UpdateAcls(acls)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action, action2}, acl.Id)

	// 4-key
	key = generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple 4-key Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
	}

	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy FastPath Check Failed!")
	}

	backward := getBackwardAcl(action)
	key = generateLookupKey(group1Mac2, group1Mac, 0, group1Ip3, group1Ip1, 6, 8000, 0)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward}, acl.Id)
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
	}

	key = generateLookupKey(group1Mac2, group1Mac, 0, group1Ip3, group1Ip1, 6, 0, 8000)
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	basicPolicyData = nil
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy FastPath Check Failed!")
	}

	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestFlowVlanAcls Check Failed!")
	}

	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward}, acl.Id)
	key = generateLookupKey(group2Mac, group1Mac, 10, group2Ip1, group1Ip1, 6, 11, 10)
	_, policyData2 := table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData2, policyData2) {
		t.Error("TestFlowVlanAcls Check Failed!")
	}

	// key不匹配，返回无效policy
	key = generateLookupKey(group2Mac, group1Mac, 11, group2Ip1, group1Ip1, 6, 11, 10)
	_, policyData3 := table.LookupAllByKey(key)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData3, policyData3) {
		t.Error("TestFlowVlanAcls Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action, backward}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestIpGroupPortAcl Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action1, action2}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 2-key: 1:10 -> 2:80 proto:1 vlan:10
	key = generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, 1, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action1, action3}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 3-key: 1:10 -> 2:80 proto:6 vlan:0
	key = generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2, action3}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action5, action4}, acl5.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 5-key 2:80->1:10 proto:6
	key = generateLookupKey(group2Mac, group1Mac, 0, group2Ip1, group1Ip1, 6, 80, 10)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	backward2 := getBackwardAcl(action5)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{backward2, backward1}, acl5.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	basicPolicyData.Merge([]AclAction{backward2, backward1}, acl5.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action1, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy FastPath Check Failed!")
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
	basicPolicyData.Merge([]AclAction{action2, backward}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key FastPath Check Failed!")
	}
	// 3-key  非资源组ip->(group5)groupIp5  3和4都可匹配action2
	ip1 := NewIPFromString("1.1.1.1").Int()
	key = generateLookupKey(0, group5Mac1, 0, ip1, groupIp5, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key FastPath Check Failed!")
	}
	// 4-key 非资源组ip->(group5)groupIp6
	key = generateLookupKey(0, group5Mac1, 0, ip1, groupIp6, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 4-key Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 4-key FastPath Check Failed!")
	}
	// 5-key (group3)groupIp3网段云外ip2:1000 -> (group5)groupIp5网段云外ip3:1023 udp
	ip2 := NewIPFromString("10.25.1.10").Int()
	ip3 := NewIPFromString("192.168.10.10").Int()
	key = generateLookupKey(group3Mac1, group5Mac1, 0, ip2, ip3, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action3, action2}, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 5-key Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 5-key FastPath Check Failed!")
	}

	// 6-key group3Mac1 + ip:1000 -> (group5)groupIp5:1023 udp,vlan:10
	//      (group3)mac和ip不对应情况下，虽能匹配到group3Id，但三层epcId=-1
	ip := NewIPFromString("10.25.2.2").Int()
	key = generateLookupKey(group3Mac1, group5Mac2, 10, ip, groupIp5, 17, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = NewPolicyData()
	basicPolicyData.Merge([]AclAction{action3, action2}, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key Check Failed!")
	}
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key FastPath Check Failed!")
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
	basicPolicyData1.Merge([]AclAction{action2, action1, backward1}, acl2.Id) // 可以匹配backward1
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group3)groupIp4 -> (group3/group6)groupIp3
	key2 := generateLookupKey(group3Mac1, group6Mac1, 0, groupIp4, groupIp3, 17, 0, 0)
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	// 不匹配backward2
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{action2, action1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key1 - FastPath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed!")
	}

	// key2 - FastPath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed!")
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
	basicPolicyData3.Merge([]AclAction{action2, action1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)groupIp4:8000 -> (group5/group6)groupIp2:6000 udp
	key4 := generateLookupKey(group4Mac1, group5Mac1, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	// 源端匹配group4不匹配group3，目的端匹配group6不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	basicPolicyData4 := NewPolicyData()
	basicPolicyData4.Merge([]AclAction{action4, action1}, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group4)group4Id:8000 -> (group5/group6)groupIp2:6000 udp
	key5 := generateLookupKey(group4Mac1, 0, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key5)
	// 源端匹配group4不匹配group3,目的端匹配group6不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key5)
	basicPolicyData5 := NewPolicyData()
	basicPolicyData5.Merge([]AclAction{action4, action1}, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
	}

	// (mac、ip不匹配) groupIp4 :8000 -> (group6)groupIp2:6000 udp
	key6 := generateLookupKey(group5Mac2, group7Mac1, 10, groupIp4, groupIp2, 17, 8000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key6)
	// 源端不匹配group3/group4,目的端匹配group6，不匹配group7
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key6)
	basicPolicyData6 := NewPolicyData()
	basicPolicyData6.Merge([]AclAction{action1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed!")
	}

	// key3 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed!")
	}

	// key5 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key5)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed!")
	}

	// key6 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key6)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FastPath Check Failed!")
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
	basicPolicyData1.Merge([]AclAction{action2, backward2, action1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2:(group6)groupIp3:6000 -> (group5)groupIp5:8000 tcp vlan:10
	key2 := generateLookupKey(group6Mac1, group5Mac1, 10, groupIp3, groupIp5, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	// 不能匹配acl1
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group5)groupIp6:8000 -> (group5)groupIp5:8000 tcp
	key3 := generateLookupKey(group5Mac2, group5Mac1, 10, groupIp6, groupIp5, 6, 8000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key3)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key3)
	// 可匹配acl1，direction=3；可匹配acl2，direction=3
	basicPolicyData3 := NewPolicyData()
	basicPolicyData3.Merge([]AclAction{action2, action1, backward2, backward1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group5)groupIp6:6000 -> (group6)groupIp3:8000 tcp vlan:11
	key4 := generateLookupKey(group5Mac1, group6Mac1, 11, groupIp6, groupIp3, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	// vlan不符，不可匹配acl2
	basicPolicyData4 := NewPolicyData()
	basicPolicyData4.Merge([]AclAction{action1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group5)groupIp5:6000 -> (group6)groupIp3:8000 udp vlan:10
	key5 := generateLookupKey(group5Mac1, group6Mac1, 10, groupIp5, groupIp3, 17, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key5)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key5)
	// udp协议，不匹配acl1
	basicPolicyData5 := NewPolicyData()
	basicPolicyData5.Merge([]AclAction{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
	}

	// key6: (group5)groupIp5:6000 -> (group6)groupIp3:6000
	key6 := generateLookupKey(group5Mac1, group6Mac1, 10, groupIp5, groupIp3, 6, 6000, 6000)
	result = table.cloudPlatformLabeler.GetEndpointData(key6)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key6)
	// port不一致，不匹配acl1
	basicPolicyData6 := NewPolicyData()
	basicPolicyData6.Merge([]AclAction{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed!")
	}

	// key7: (group5)groupIp5:6000 -> (group6)groupIp3:8000 vlan:11 tcp
	key7 := generateLookupKey(group5Mac1, group6Mac1, 11, groupIp5, groupIp3, 6, 6000, 8000)
	result = table.cloudPlatformLabeler.GetEndpointData(key7)
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key7)
	// vlan不符，不匹配acl2
	basicPolicyData7 := NewPolicyData()
	basicPolicyData7.Merge([]AclAction{action1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData7, policyData) {
		t.Error("key7 FirstPath Check Failed")
	}

	// key1 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed!")
	}

	// key2 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed!")
	}

	// key3 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed!")
	}

	// key5 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key5)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed!")
	}

	// key6 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key6)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FastPath Check Failed!")
	}

	// key7 - fastpath
	_, policyData = table.policyLabeler.GetPolicyByFastPath(key7)
	if !CheckPolicyResult(t, basicPolicyData7, policyData) {
		t.Error("key7 FastPath Check Failed!")
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
	basicEndpointData1 := NewEndpointData()
	basicEndpointData1.SrcInfo = table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	basicEndpointData1.DstInfo = table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	if !CheckEndpointDataResult(t, basicEndpointData1, result) {
		t.Error("key1 EndpointData Check Failed!")
	}
	policyData := table.policyLabeler.GetPolicyByFirstPath(result, key1)
	basicPolicyData1 := NewPolicyData()
	basicPolicyData1.Merge([]AclAction{action2, action1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group4)groupIp4:1000 -> (group3/group6)groupIp3:1023 tcp
	key2 := generateLookupKey(group4Mac1, group3Mac1, 0, groupIp4, groupIp3, 6, 1000, 1023)
	// src: DEV-40 dst: DEV-30, IP-60
	result = table.cloudPlatformLabeler.GetEndpointData(key2)
	basicEndpointData2 := NewEndpointData()
	basicEndpointData2.SrcInfo = table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	basicEndpointData2.DstInfo = table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	if !CheckEndpointDataResult(t, basicEndpointData2, result) {
		t.Error("key2 EndpointData Check Failed!")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key2)
	backward1 := getBackwardAcl(action1)
	backward2 := getBackwardAcl(action2)
	basicPolicyData2 := NewPolicyData()
	basicPolicyData2.Merge([]AclAction{backward2, backward1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group3/group6)groupIp3:1000 -> (group4)groupIp4:1023 tcp
	key3 := generateLookupKey(group3Mac1, group4Mac1, 0, groupIp3, groupIp4, 6, 1000, 1023)
	// src: DEV-30, IP-60 dst: DEV-40
	result = table.cloudPlatformLabeler.GetEndpointData(key3)
	basicEndpointData3 := NewEndpointData()
	basicEndpointData3.SrcInfo = table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	basicEndpointData3.DstInfo = table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	if !CheckEndpointDataResult(t, basicEndpointData3, result) {
		t.Error("key3 EndpointData Check Failed!")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key3)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)groupIp4:1023 -> (group3/group6)groupIp3:1000 tcp
	key4 := generateLookupKey(group4Mac1, group3Mac1, 0, groupIp4, groupIp3, 6, 1023, 1000)
	// src: DEV-40 dst: DEV-30, IP-60
	result = table.cloudPlatformLabeler.GetEndpointData(key4)
	basicEndpointData4 := NewEndpointData()
	basicEndpointData4.SrcInfo = table.cloudPlatformLabeler.GetEndpointInfo(group4Mac1, groupIp4, TAP_TOR)
	basicEndpointData4.DstInfo = table.cloudPlatformLabeler.GetEndpointInfo(group3Mac1, groupIp3, TAP_TOR)
	if !CheckEndpointDataResult(t, basicEndpointData4, result) {
		t.Error("key4 EndpointData Check Failed!")
	}
	policyData = table.policyLabeler.GetPolicyByFirstPath(result, key4)
	basicPolicyData4 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed")
	}

	// key1 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key1)
	if !CheckEndpointDataResult(t, basicEndpointData1, result) {
		t.Error("key1 EndpointData Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("FastPath Check Failed!")
	}

	// key2 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key2)
	if !CheckEndpointDataResult(t, basicEndpointData2, result) {
		t.Error("key2 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed!")
	}

	// key3 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key3)
	if !CheckEndpointDataResult(t, basicEndpointData3, result) {
		t.Error("key3 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	result, policyData = table.policyLabeler.GetPolicyByFastPath(key4)
	if !CheckEndpointDataResult(t, basicEndpointData4, result) {
		t.Error("key4 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed!")
	}
}

func BenchmarkFirstPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)
	endpoint := table.cloudPlatformLabeler.GetEndpointData(key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	}
}

func BenchmarkFastPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group1Id, group2Id, 6, 8000, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, 0, group1Ip1, group2Ip1, 6, 0, 8000)
	endpoint := table.cloudPlatformLabeler.GetEndpointData(key)
	table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.policyLabeler.GetPolicyByFastPath(key)
	}
}
