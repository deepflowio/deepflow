package policy

import (
	"reflect"
	"testing"

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
	ip5           = NewIPFromString("1.1.1.1").Int()
	ip6           = NewIPFromString("10.25.1.10").Int()
	ip7           = NewIPFromString("192.168.10.10").Int()
	ip8           = NewIPFromString("10.25.2.2").Int()
	ip9           = NewIPFromString("172.16.10.10").Int()
	ip10          = NewIPFromString("172.16.10.20").Int()
	ip11          = NewIPFromString("255.255.255.255").Int()
	ipNet1        = "192.168.0.12/24"
	ipNet10       = "10.90.0.0/16"
	ipNet11       = "10.90.9.0/24"
	ipNet12       = "10.0.0.0/8"
	ipNet13       = "10.90.0.0/16"
	ipNet14       = "10.90.9.123/32"
	ipNet15       = "0.0.0.0/0"
	groupEpcOther = int32(-1)
	groupEpcAny   = int32(0)
	groupAny      = uint32(0)
	subnetAny     = uint32(0)
	protoAny      = IPProtocol(0)
	vlanAny       = uint32(0)
	macAny        = uint64(0)
	mac1          = NewMACAddrFromString("08:00:27:a4:2b:f0").Int()
	mac2          = NewMACAddrFromString("08:00:27:a4:2b:fa").Int()
	mac3          = NewMACAddrFromString("08:00:27:a4:2b:fb").Int()
	mac4          = NewMACAddrFromString("08:00:27:a4:2b:fc").Int()
	mac5          = NewMACAddrFromString("08:00:27:a4:2b:fd").Int()
	launchServer1 = NewIPFromString("10.10.10.10").Int()
	l2EndBool     = []bool{false, true}
	l3EndBool     = []bool{false, true}
)

// 和云平台结合起来的测试例所需常量定义
var (
	server = NewIPFromString("172.20.1.1").Int()

	group    = []uint32{0, 10, 20, 30, 40, 50, 60, 70, 2, 3, 4, 11, 12, 13, 14, 15}
	groupEpc = []int32{0, 10, 20, 0, 40, 50, 0, 70, 40, 11, 12}
	ipGroup6 = group[6] + IP_GROUP_ID_FLAG

	group1Ip1  = NewIPFromString("192.168.1.10").Int()
	group1Ip2  = NewIPFromString("192.168.1.20").Int()
	group1Ip3  = NewIPFromString("102.168.33.22").Int()
	group1Mac  = NewMACAddrFromString("11:11:11:11:11:11").Int()
	group1Mac2 = NewMACAddrFromString("11:11:11:11:11:12").Int()

	group2Ip1 = NewIPFromString("10.30.1.10").Int()
	group2Ip2 = NewIPFromString("10.30.1.20").Int()
	group2Mac = NewMACAddrFromString("22:22:22:22:22:22").Int()

	group3Ip1  = NewIPFromString("192.168.20.112").Int() // group3/group4
	group3Ip2  = NewIPFromString("172.16.1.200").Int()   // group3/group4
	group3Mac1 = NewMACAddrFromString("33:33:33:33:33:31").Int()

	group4Ip1  = NewIPFromString("192.168.20.112").Int() // group3/group4
	group4Ip2  = NewIPFromString("172.16.1.200").Int()   // group3/group4
	group4Mac1 = NewMACAddrFromString("44:44:44:44:44:41").Int()

	group5Ip1  = NewIPFromString("172.16.2.100").Int()
	group5Ip2  = NewIPFromString("10.33.1.10").Int()
	group5Mac1 = NewMACAddrFromString("55:55:55:55:55:51").Int()
	group5Mac2 = NewMACAddrFromString("55:55:55:55:55:52").Int()

	ipGroup3IpNet1 = "10.25.1.2/24"

	ipGroup5IpNet1 = "192.168.10.10/24" // ipGroup5/ipGroup6/ipGroup7
	ipGroup5Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup5Ip2    = NewIPFromString("192.168.10.123").Int()
	ipGroup5Mac1   = NewMACAddrFromString("55:55:55:55:55:51").Int()

	ipGroup6IpNet1 = "192.168.10.10/24"  // ipGroup5/ipGroup6/ipGroup7
	ipGroup6IpNet2 = "192.168.20.112/32" // ipGroup6/ipGroup7
	ipGroup6Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup6Ip2    = NewIPFromString("192.168.20.112").Int()
	ipGroup6Ip3    = NewIPFromString("192.168.10.123").Int()
	ipGroup6Mac1   = NewMACAddrFromString("66:66:66:66:66:61").Int()

	ipGroup7IpNet1 = "192.168.10.10/24"  // ipGroup5/ipGroup6/ipGroup7
	ipGroup7IpNet2 = "192.168.20.112/32" // ipGroup6/ipGroup7
	ipGroup7Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup7Ip2    = NewIPFromString("192.168.20.112").Int()
	ipGroup7Ip3    = NewIPFromString("192.168.10.123").Int()
	ipGroup7Mac1   = NewMACAddrFromString("77:77:77:77:77:71").Int()
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

func generateEndpointInfo(l2EpcId, l3EpcId int32, l2End, l3End bool, subnetId uint32, groupId ...uint32) *EndpointInfo {
	basicEndpointInfo := &EndpointInfo{
		L2EpcId:      l2EpcId,
		L2DeviceType: 2,
		L2DeviceId:   3,
		L2End:        l2End,
		L3EpcId:      l3EpcId,
		L3DeviceType: 2,
		L3DeviceId:   3,
		L3End:        l3End,
		HostIp:       server,
		SubnetId:     subnetId,
	}
	basicEndpointInfo.GroupIds = append(basicEndpointInfo.GroupIds, groupId...)
	return basicEndpointInfo
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

func generatePlatformDataByParam(ip uint32, mac uint64, epcId int32, Iftype uint32) *PlatformData {
	ipInfo := generateIpNet(ip, 121, 32)
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

func generatePolicyAcl(table *PolicyTable, action AclAction, aclID ACLID, args ...interface{}) *Acl {
	var srcGroupId, dstGroupId, vlan uint32
	var proto uint8
	var port uint16
	var npb NpbAction

	for i, arg := range args {
		switch i {
		case 0:
			srcGroupId = arg.(uint32)
		case 1:
			dstGroupId = arg.(uint32)
		case 2:
			proto = uint8(arg.(IPProtocol))
		case 3:
			if _, ok := arg.(uint16); ok {
				port = arg.(uint16)
			} else {
				port = uint16(arg.(int))
			}
		case 4:
			if _, ok := arg.(int); ok {
				vlan = uint32(arg.(int))
			} else {
				vlan = arg.(uint32)
			}
		case 5:
			npb = arg.(NpbAction)
		}
	}

	srcGroups := make([]uint32, 0, 1)
	dstGroups := make([]uint32, 0, 1)
	dstPorts := make([]PortRange, 0, 1)

	srcGroups = append(srcGroups, srcGroupId)
	dstGroups = append(dstGroups, dstGroupId)
	if port != 0 {
		dstPorts = append(dstPorts, NewPortRange(port, port))
	}
	acl := &Acl{
		Id:           aclID,
		Type:         TAP_TOR,
		TapId:        uint32(aclID + 1),
		SrcGroups:    srcGroups,
		DstGroups:    dstGroups,
		DstPortRange: dstPorts,
		Proto:        uint8(proto),
		Vlan:         vlan,
		Action:       []AclAction{action},
	}
	if npb != 0 {
		acl.NpbActions = append(acl.NpbActions, npb)
	}
	return acl
}

func generateLookupKey(srcMac, dstMac uint64, vlan uint32, srcIp, dstIp uint32,
	proto IPProtocol, srcPort, dstPort uint16) *LookupKey {
	key := &LookupKey{
		SrcMac:  srcMac,
		DstMac:  dstMac,
		SrcIp:   srcIp,
		DstIp:   dstIp,
		Proto:   uint8(proto),
		SrcPort: srcPort,
		DstPort: dstPort,
		Vlan:    uint16(vlan),
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
	ipGroups := make([]*IpGroupData, 0, 3)
	// groupEpc[8] = groupEpc[4], group[8] != group[4]
	ipGroup1 := generateIpGroup(group[4], groupEpc[4], ipNet1)
	ipGroup2 := generateIpGroup(group[5], groupEpc[5], ipNet1)
	ipGroup3 := generateIpGroup(group[8], groupEpc[8], ipNet1)

	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3)
	policy.UpdateIpGroupData(ipGroups)
}

// 生成特定平台信息
func generatePlatformData(policy *PolicyTable) {
	// epcId:40 IfType:4
	datas := make([]*PlatformData, 0, 2)
	vifData := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	datas = append(datas, vifData)

	policy.UpdateInterfaceData(datas)
}

// 生成特定平台和资源组信息
func generatePolicyTable() *PolicyTable {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	datas := make([]*PlatformData, 0, 2)
	ipGroups := make([]*IpGroupData, 0, 3)

	ip1 := generateIpNet(group1Ip1, 121, 32)
	ip2 := generateIpNet(group1Ip2, 121, 32)
	data1 := generatePlatformDataWithGroupId(groupEpc[1], group[1], group1Mac, ip1, ip2)

	ip1 = generateIpNet(group1Ip3, 121, 32)
	data2 := generatePlatformDataWithGroupId(groupEpcAny, groupAny, group1Mac2, ip1)

	ip1 = generateIpNet(group2Ip1, 122, 32)
	ip2 = generateIpNet(group2Ip2, 122, 32)
	data3 := generatePlatformDataWithGroupId(groupEpc[2], group[2], group2Mac, ip1, ip2)
	datas = append(datas, data1, data2, data3)

	ip1 = generateIpNet(group3Ip1, 121, 24)
	ip2 = generateIpNet(group3Ip2, 121, 32)
	// group3无epc，group4有epc  ip:group3Ip1/group4Ip1 + group3Ip2/group4Ip2
	data1 = generatePlatformDataWithGroupId(groupEpc[3], group[3], group3Mac1, ip1, ip2)

	ip1 = generateIpNet(group4Ip1, 121, 24)
	ip2 = generateIpNet(group4Ip2, 121, 32)
	data2 = generatePlatformDataWithGroupId(groupEpc[4], group[4], group4Mac1, ip1, ip2)

	ip1 = generateIpNet(group5Ip1, 121, 24)
	ip2 = generateIpNet(group5Ip2, 121, 32)
	// group5有epc和无epc ip:group5Ip1 + group5Ip2
	data3 = generatePlatformDataWithGroupId(groupEpc[5], group[5], group5Mac2, ip1, ip2)
	groupEpc[5] = groupEpcAny
	data4 := generatePlatformDataWithGroupId(groupEpc[5], group[5], group5Mac1, ip1, ip2)
	datas = append(datas, data1, data2, data3, data4)

	policy.UpdateInterfaceData(datas)

	ipGroup1 := generateIpGroup(group[3], groupEpc[3], ipGroup3IpNet1)
	ipGroup2 := generateIpGroup(group[5], groupEpc[5], ipGroup5IpNet1)
	groupEpc[5] = 50
	ipGroup3 := generateIpGroup(group[6], groupEpc[6], ipGroup6IpNet1, ipGroup6IpNet2)
	ipGroup4 := generateIpGroup(group[7], groupEpc[7], ipGroup7IpNet1, ipGroup7IpNet2)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3, ipGroup4)

	policy.UpdateIpGroupData(ipGroups)

	return policy
}

// 生成特定Acl规则
func generateAclData(policy *PolicyTable) {
	dstPorts := []uint16{0, 8000}
	aclAction1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, dstPorts[1], vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolTCP, dstPorts[0], 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})
}

func getEndpointData(table *PolicyTable, key *LookupKey) *EndpointData {
	endpoint := table.cloudPlatformLabeler.GetEndpointData(key)
	if endpoint != nil {
		endpoint = table.cloudPlatformLabeler.UpdateEndpointData(endpoint, key)
	}
	return endpoint
}

func getPolicyByFastPath(table *PolicyTable, key *LookupKey) (*EndpointData, *PolicyData) {
	endpoint, policy := table.policyLabeler.GetPolicyByFastPath(key)
	if endpoint != nil {
		endpoint = table.cloudPlatformLabeler.UpdateEndpointData(endpoint, key)
	}
	return endpoint, policy
}

func getPolicyByFirstPath(table *PolicyTable, endpoint *EndpointData, key *LookupKey) *PolicyData {
	_, policy := table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	return policy
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

// 以下是云平台信息和policy结合起来的测试
func TestPolicySimple(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple Check Failed!")
	}

	// 构建查询2-key  2:8000->1:0 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 0)
	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	// 查询结果和预期结果比较
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple 2-key Check Failed!")
	}

	// 构建无效查询3-key  2:0->1:8000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// key不匹配，返回无效policy
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySimple 3-key Check Failed!")
	}

	// 测试同样的key, 匹配两条action
	action2 := generateAclAction(12, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl2)
	table.UpdateAcls(acls)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action, action2}, nil, acl.Id)

	// 4-key
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
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
	acl := generatePolicyAcl(table, action, 10, group[1], groupAny, IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group1Mac2, vlanAny, group1Ip1, group1Ip3, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
	}

	_, policyData = getPolicyByFastPath(table, key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy FastPath Check Failed!")
	}

	backward := getBackwardAcl(action)
	key = generateLookupKey(group1Mac2, group1Mac, vlanAny, group1Ip3, group1Ip1, IPProtocolTCP, 8000, 0)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	_, policyData = getPolicyByFastPath(table, key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
	}

	key = generateLookupKey(group1Mac2, group1Mac, vlanAny, group1Ip3, group1Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = getPolicyByFastPath(table, key)
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
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, 10)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1->2 tcp vlan:10
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, IPProtocolTCP, 11, 10)
	_, policyData := table.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestFlowVlanAcls Check Failed!")
	}

	// key和acl方向相反，构建反向的action
	backward := getBackwardAcl(action)
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]AclAction{backward}, nil, acl.Id)
	key = generateLookupKey(group2Mac, group1Mac, 10, group2Ip1, group1Ip1, IPProtocolTCP, 11, 10)
	_, policyData2 := getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData2, policyData2) {
		t.Error("TestFlowVlanAcls Check Failed!")
	}

	// key不匹配，返回无效policy
	key = generateLookupKey(group2Mac, group1Mac, 11, group2Ip1, group1Ip1, IPProtocolTCP, 11, 10)
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
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 20, 10)
	// group2->group1,tcp,vlan:10,dstport:21
	action2 := generateAclAction(12, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group[2], group[1], IPProtocolTCP, 21, 10)
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)
	// 构建查询key  1:21->2:20 tcp vlan:10 ,匹配两条acl
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, IPProtocolTCP, 21, 20)
	_, policyData := table.LookupAllByKey(key)
	backward := getBackwardAcl(action2)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action, backward}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestIpGroupPortAcl Check Failed!")
	}
}

func TestVlanProtoPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable()
	// group1->group2, vlan:10
	action1 := generateAclAction(11, ACTION_FLOW_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 11, group[1], group[2], protoAny, 0, 10)
	// group1->group2, proto:6
	action2 := generateAclAction(12, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 12, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	// group1->group2, port:80
	action3 := generateAclAction(13, ACTION_FLOW_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 13, group[1], group[2], protoAny, 80, vlanAny)
	acls = append(acls, acl1, acl2, acl3)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:10->2:10 proto:6 vlan:10
	key := generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, IPProtocolTCP, 10, 10)
	// 获取first查询结果
	_, policyData := table.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action1, action2}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 2-key: 1:10 -> 2:80 proto:1 vlan:10
	key = generateLookupKey(group1Mac, group2Mac, 10, group1Ip1, group2Ip1, IPProtocolICMPv4, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action1, action3}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 3-key: 1:10 -> 2:80 proto:6 vlan:0
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action3, action2}, nil, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}

	acls = []*Acl{}
	table = generatePolicyTable()
	// port:80
	action4 := generateAclAction(14, ACTION_FLOW_COUNTING)
	acl4 := generatePolicyAcl(table, action4, 14, groupAny, groupAny, protoAny, 80, vlanAny)
	// group1->group2, proto:6
	action5 := generateAclAction(15, ACTION_FLOW_COUNTING)
	acl5 := generatePolicyAcl(table, action5, 15, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acls = append(acls, acl4, acl5)
	table.UpdateAcls(acls)
	// 4-key  1:10->2:80 proto:6
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 10, 80)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	backward1 := getBackwardAcl(action4)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action4, action5}, nil, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}
	// 5-key 2:80->1:10 proto:6
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 80, 10)
	// 获取first查询结果
	_, policyData = table.LookupAllByKey(key)
	backward2 := getBackwardAcl(action5)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward1, backward2}, nil, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	basicPolicyData.Merge([]AclAction{backward1, backward2}, nil, acl4.Id)
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
	acl1 := generatePolicyAcl(table, action1, 16, groupAny, group[1], protoAny, 0, vlanAny)
	acls = append(acls, acl1)
	table.UpdateAcls(acls)
	// 构建查询1-key  (group1)group1Ip1:10->(group1)group1Ip2:10 proto:6 vlan:10
	key := generateLookupKey(group1Mac, group1Mac, 10, group1Ip1, group1Ip2, IPProtocolTCP, 10, 10)
	_, policyData := table.LookupAllByKey(key)
	backward := getBackwardAcl(action1)
	// 可匹配acl1，direction=3
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action1, backward}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy FastPath Check Failed!")
	}

	acls = []*Acl{}
	table = generatePolicyTable()
	// acl2: dstGroup:group5
	// acl3: srcGroup:group3-> dstGroup:group5,dstPort=1023,udp
	// group5: 1.epcId=0,mac=group5Mac1,ips="group5Ip1/24,group5Ip2/32"
	//         2.epcId=50,mac=group5Mac2,ips="group5Ip1/24,group5Ip2/32"
	action2 := generateAclAction(18, ACTION_FLOW_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 18, groupAny, group[5], protoAny, 0, vlanAny)
	action3 := generateAclAction(19, ACTION_FLOW_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 19, group[3], group[5], IPProtocolUDP, 1023, vlanAny)
	acls = append(acls, acl2, acl3)
	table.UpdateAcls(acls)
	// 2-key  (group5)group5Ip1:1000->(group5)group5Ip2:1023 udp
	key = generateLookupKey(group5Mac1, group5Mac1, vlanAny, group5Ip1, group5Ip2, IPProtocolUDP, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	backward = getBackwardAcl(action2)
	// 匹配action2及backward，但不匹配action3
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action2, backward}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key FastPath Check Failed!")
	}
	// 3-key  非资源组ip5->(group5)group5Ip1  3和4都可匹配action2
	key = generateLookupKey(macAny, group5Mac1, vlanAny, ip5, group5Ip1, IPProtocolUDP, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action2}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key FastPath Check Failed!")
	}
	// 4-key 非资源组ip1->(group5)group5Ip2
	key = generateLookupKey(macAny, group5Mac1, vlanAny, ip1, group5Ip2, IPProtocolUDP, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action2}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 4-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 4-key FastPath Check Failed!")
	}
	// 5-key (group3)group3Ip1网段云外ip6:1000 -> (group5)group5Ip1网段云外ip7:1023 udp
	key = generateLookupKey(group3Mac1, group5Mac1, vlanAny, ip6, ip7, IPProtocolUDP, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action3, action2}, nil, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 5-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 5-key FastPath Check Failed!")
	}

	// 6-key group3Mac1 + ip8:1000 -> (group5)group5Ip1:1023 udp,vlan:10
	//      (group3)mac和ip不对应情况下，虽能匹配到group3，但三层epcId=-1
	key = generateLookupKey(group3Mac1, group5Mac2, 10, ip8, group5Ip1, IPProtocolUDP, 1000, 1023)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action3, action2}, nil, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key FastPath Check Failed!")
	}
}

func TestSrcDevGroupDstIpGroupPolicy(t *testing.T) {
	table := generatePolicyTable()
	acls := []*Acl{}
	// acl1: dstGroup: ipGroup6(IP资源组)，udp
	// acl2: srcGroup: group3(DEV资源组)，udp
	action1 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl1 := generatePolicyAcl(table, action1, 20, groupAny, group[6], IPProtocolUDP, 0, vlanAny)
	action2 := generateAclAction(21, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 21, group[3], groupAny, IPProtocolUDP, 0, vlanAny)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group3/ipGroup6)group3Ip1 -> (ipGroup6)ipGroup6Ip3 udp
	key1 := generateLookupKey(group3Mac1, ipGroup6Mac1, vlanAny, group3Ip1, ipGroup6Ip3, IPProtocolUDP, 0, 0)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	backward1 := getBackwardAcl(action1)
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.Merge([]AclAction{action2, action1, backward1}, nil, acl2.Id) // 可以匹配backward1
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group3)group3Ip2 -> (group3/ipGroup6)group3Ip1
	key2 := generateLookupKey(group3Mac1, ipGroup6Mac1, vlanAny, group3Ip2, group3Ip1, IPProtocolUDP, 0, 0)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	// 不匹配backward2
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]AclAction{action2, action1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key1 - FastPath
	_, policyData = getPolicyByFastPath(table, key1)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed!")
	}

	// key2 - FastPath
	_, policyData = getPolicyByFastPath(table, key2)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed!")
	}

	// acl3: dstGroup: ipGroup7(IP资源组)： 和ipGroup6所含IP相同，但有epc限制 udp
	// acl4: srcGroup: group4(DEV资源组): 和group3所含IP相同，但有epc限制 udp
	action3 := generateAclAction(22, ACTION_PACKET_COUNTING)
	acl3 := generatePolicyAcl(table, action3, 22, groupAny, group[7], IPProtocolUDP, 0, vlanAny)
	action4 := generateAclAction(23, ACTION_PACKET_COUNTING)
	acl4 := generatePolicyAcl(table, action4, 23, group[4], groupAny, IPProtocolUDP, 0, vlanAny)
	acls = append(acls, acl3, acl4)
	table.UpdateAcls(acls)

	// key3: (group3)group3Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp vlan:10
	key3 := generateLookupKey(group3Mac1, macAny, 10, group3Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key3)
	// 匹配ipGroup6、group3，ipGroup7有epc限制，group4mac不符
	policyData = getPolicyByFirstPath(table, result, key3)
	basicPolicyData3 := new(PolicyData)
	basicPolicyData3.Merge([]AclAction{action2, action1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key4 := generateLookupKey(group4Mac1, group5Mac1, 10, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key4)
	// 源端匹配group4不匹配group3，目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key4)
	basicPolicyData4 := new(PolicyData)
	basicPolicyData4.Merge([]AclAction{action4, action1}, nil, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key5 := generateLookupKey(group4Mac1, macAny, 10, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key5)
	// 源端匹配group4不匹配group3,目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key5)
	basicPolicyData5 := new(PolicyData)
	basicPolicyData5.Merge([]AclAction{action4, action1}, nil, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
	}

	// key6: (mac、ip不匹配) group3Ip2 :8000 -> (ipGroup6/ipGroup7)ipGroup7Ip3:6000 udp
	key6 := generateLookupKey(group5Mac2, ipGroup7Mac1, 10, group3Ip2, ipGroup7Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key6)
	// 源端不匹配group3/group4,目的端匹配ipGroup6，不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key6)
	basicPolicyData6 := new(PolicyData)
	basicPolicyData6.Merge([]AclAction{action1}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed!")
	}

	// key3 - fastpath
	_, policyData = getPolicyByFastPath(table, key3)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	_, policyData = getPolicyByFastPath(table, key4)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed!")
	}

	// key5 - fastpath
	_, policyData = getPolicyByFastPath(table, key5)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed!")
	}

	// key6 - fastpath
	_, policyData = getPolicyByFastPath(table, key6)
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
	acl1 := generatePolicyAcl(table, action1, 24, group[5], groupAny, IPProtocolTCP, 8000, vlanAny)
	action2 := generateAclAction(25, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 25, group[5], groupAny, protoAny, 0, 10)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group5)group5Ip1:6000 -> (ipGroup5/ipGroup6)ipGroup6Ip3:8000 tcp vlan:10
	key1 := generateLookupKey(group5Mac1, ipGroup6Mac1, 10, group5Ip1, ipGroup6Ip3, IPProtocolTCP, 6000, 8000)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	// 可匹配acl1，direction=3; 可匹配acl2，direction=1
	backward1 := getBackwardAcl(action1)
	backward2 := getBackwardAcl(action2)
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.Merge([]AclAction{action2, backward2, action1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2:(ipGroup6)ipGroup6Ip2:6000 -> (group5)group5Ip1:8000 tcp vlan:10
	key2 := generateLookupKey(ipGroup6Mac1, group5Mac1, 10, ipGroup6Ip2, group5Ip1, IPProtocolTCP, 6000, 8000)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	// 不能匹配acl1
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]AclAction{backward2}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group5)group5Ip2:8000 -> (group5)group5Ip1:8000 tcp
	key3 := generateLookupKey(group5Mac2, group5Mac1, 10, group5Ip2, group5Ip1, IPProtocolTCP, 8000, 8000)
	result = getEndpointData(table, key3)
	policyData = getPolicyByFirstPath(table, result, key3)
	// 可匹配acl1，direction=3；可匹配acl2，direction=3
	basicPolicyData3 := new(PolicyData)
	basicPolicyData3.Merge([]AclAction{action2, action1, backward2, backward1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group5)group5Ip2:6000 -> (ipGroup6)ipGroup6Ip1:8000 tcp vlan:11
	key4 := generateLookupKey(group5Mac1, ipGroup6Mac1, 11, group5Ip2, ipGroup6Ip1, IPProtocolTCP, 6000, 8000)
	result = getEndpointData(table, key4)
	policyData = getPolicyByFirstPath(table, result, key4)
	// vlan不符，不可匹配acl2
	basicPolicyData4 := new(PolicyData)
	basicPolicyData4.Merge([]AclAction{action1}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group5)group5Ip1:6000 -> (ipGroup6)ipGroup6Ip2:8000 udp vlan:10
	key5 := generateLookupKey(group5Mac1, ipGroup6Mac1, 10, group5Ip1, ipGroup6Ip2, IPProtocolUDP, 6000, 8000)
	result = getEndpointData(table, key5)
	policyData = getPolicyByFirstPath(table, result, key5)
	// udp协议，不匹配acl1
	basicPolicyData5 := new(PolicyData)
	basicPolicyData5.Merge([]AclAction{action2}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
	}

	// key6: (group5)group5Ip1:6000 -> (ipGroup6)ipGroup6Ip2:6000
	key6 := generateLookupKey(group5Mac1, ipGroup6Mac1, 10, group5Ip1, ipGroup6Ip2, IPProtocolTCP, 6000, 6000)
	result = getEndpointData(table, key6)
	policyData = getPolicyByFirstPath(table, result, key6)
	// port不一致，不匹配acl1
	basicPolicyData6 := new(PolicyData)
	basicPolicyData6.Merge([]AclAction{action2}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FirstPath Check Failed!")
	}

	// key7: (group5)group5Ip1:6000 -> (ipGroup6)ipGroup6Ip2:8000 vlan:11 tcp
	key7 := generateLookupKey(group5Mac1, ipGroup6Mac1, 11, group5Ip1, ipGroup6Ip2, IPProtocolTCP, 6000, 8000)
	result = getEndpointData(table, key7)
	policyData = getPolicyByFirstPath(table, result, key7)
	// vlan不符，不匹配acl2
	basicPolicyData7 := new(PolicyData)
	basicPolicyData7.Merge([]AclAction{action1}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData7, policyData) {
		t.Error("key7 FirstPath Check Failed")
	}

	// key1 - fastpath
	_, policyData = getPolicyByFastPath(table, key1)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FastPath Check Failed!")
	}

	// key2 - fastpath
	_, policyData = getPolicyByFastPath(table, key2)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FastPath Check Failed!")
	}

	// key3 - fastpath
	_, policyData = getPolicyByFastPath(table, key3)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	_, policyData = getPolicyByFastPath(table, key4)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FastPath Check Failed!")
	}

	// key5 - fastpath
	_, policyData = getPolicyByFastPath(table, key5)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FastPath Check Failed!")
	}

	// key6 - fastpath
	_, policyData = getPolicyByFastPath(table, key6)
	if !CheckPolicyResult(t, basicPolicyData6, policyData) {
		t.Error("key6 FastPath Check Failed!")
	}

	// key7 - fastpath
	_, policyData = getPolicyByFastPath(table, key7)
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
	acl1 := generatePolicyAcl(table, action1, 25, groupAny, group[4], IPProtocolTCP, 1000, vlanAny)
	action2 := generateAclAction(26, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(table, action2, 26, group[3], groupAny, IPProtocolTCP, 1000, vlanAny)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)
	// key1: (group3/ipGroup6)group3Ip1:1023 -> (group4)group4Ip2:1000 tcp
	key1 := generateLookupKey(group3Mac1, group4Mac1, vlanAny, group3Ip1, group4Ip2, IPProtocolTCP, 1023, 1000)
	// src: DEV-30, IP-60 dst: DEV-40
	result := getEndpointData(table, key1)
	basicData1 := new(EndpointData)
	basicData1.SrcInfo = generateEndpointInfo(groupEpc[3], groupEpcOther, l2EndBool[0], l3EndBool[0], subnetAny, group[3], ipGroup6)
	basicData1.DstInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], 121, group[4])
	if !CheckEndpointDataResult(t, basicData1, result) {
		t.Error("key1 EndpointData Check Failed!")
	}
	policyData1 := getPolicyByFirstPath(table, result, key1)
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.Merge([]AclAction{action2, action1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData1) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group4)group4Ip2:1000 -> (group3/ipGroup6)group3Ip1:1023 tcp
	key2 := generateLookupKey(group4Mac1, group3Mac1, vlanAny, group4Ip2, group3Ip1, IPProtocolTCP, 1000, 1023)
	// src: DEV-40 dst: DEV-30, IP-60
	result = getEndpointData(table, key2)
	basicData2 := new(EndpointData)
	basicData2.SrcInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], 121, group[4])
	basicData2.DstInfo = generateEndpointInfo(groupEpc[3], groupEpcOther, l2EndBool[0], l3EndBool[0], subnetAny, group[3], ipGroup6)
	if !CheckEndpointDataResult(t, basicData2, result) {
		t.Error("key2 EndpointData Check Failed!")
	}
	policyData2 := getPolicyByFirstPath(table, result, key2)
	backward1 := getBackwardAcl(action1)
	backward2 := getBackwardAcl(action2)
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]AclAction{backward2, backward1}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData2) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group3/ipGroup6)group3Ip1:1000 -> (group4)group4Ip2:1023 tcp
	key3 := generateLookupKey(group3Mac1, group4Mac1, vlanAny, group3Ip1, group4Ip2, IPProtocolTCP, 1000, 1023)
	// src: DEV-30, IP-60 dst: DEV-40
	result = getEndpointData(table, key3)
	basicData3 := new(EndpointData)
	basicData3.SrcInfo = generateEndpointInfo(groupEpc[3], groupEpcOther, l2EndBool[0], l3EndBool[0], subnetAny, group[3], ipGroup6)
	basicData3.DstInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], 121, group[4])
	if !CheckEndpointDataResult(t, basicData3, result) {
		t.Error("key3 EndpointData Check Failed!")
	}
	policyData3 := getPolicyByFirstPath(table, result, key3)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData3, policyData3) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)group4Ip2:1023 -> (group3/ipGroup6)group3Ip1:1000 tcp
	key4 := generateLookupKey(group4Mac1, group3Mac1, vlanAny, group4Ip2, group3Ip1, 6, 1023, 1000)
	// src: DEV-40 dst: DEV-30, IP-60
	result = getEndpointData(table, key4)
	basicData4 := new(EndpointData)
	basicData4.SrcInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], 121, group[4])
	basicData4.DstInfo = generateEndpointInfo(groupEpc[3], groupEpcOther, l2EndBool[0], l3EndBool[0], subnetAny, group[3], ipGroup6)
	if !CheckEndpointDataResult(t, basicData4, result) {
		t.Error("key4 EndpointData Check Failed!")
	}
	policyData4 := getPolicyByFirstPath(table, result, key4)
	basicPolicyData4 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData4, policyData4) {
		t.Error("key4 FirstPath Check Failed")
	}

	// key1 - fastpath
	result, policyData1 = getPolicyByFastPath(table, key1)
	if !CheckEndpointDataResult(t, basicData1, result) {
		t.Error("key1 EndpointData Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData1, policyData1) {
		t.Error("FastPath Check Failed!")
	}

	// key2 - fastpath
	result, policyData2 = getPolicyByFastPath(table, key2)
	if !CheckEndpointDataResult(t, basicData2, result) {
		t.Error("key2 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData2, policyData2) {
		t.Error("key2 FastPath Check Failed!")
	}

	// key3 - fastpath
	result, policyData3 = getPolicyByFastPath(table, key3)
	if !CheckEndpointDataResult(t, basicData3, result) {
		t.Error("key3 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData3, policyData3) {
		t.Error("key3 FastPath Check Failed!")
	}

	// key4 - fastpath
	result, policyData4 = getPolicyByFastPath(table, key4)
	if !CheckEndpointDataResult(t, basicData4, result) {
		t.Error("key4 EndpointData FastPath Check Failed!")
	}
	if !CheckPolicyResult(t, basicPolicyData4, policyData4) {
		t.Error("key4 FastPath Check Failed!")
	}
}

func TestNpbAction(t *testing.T) {
	table := generatePolicyTable()
	acls := []*Acl{}

	action1 := generateAclAction(25, ACTION_PACKET_BROKERING)
	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb1 := ToNpbAction(10, 150, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 100)
	npb2 := ToNpbAction(10, 100, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 200)
	npb3 := ToNpbAction(20, 200, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 200)
	npb := ToNpbAction(10, 150, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 200)

	acl1 := generatePolicyAcl(table, action1, 25, groupAny, groupAny, IPProtocolTCP, 1000, vlanAny, npb1)
	action2 := generateAclAction(26, ACTION_PACKET_BROKERING)
	// acl2 Group: 0 -> 0 Port: 1000 Proto: 0 vlan: any
	acl2 := generatePolicyAcl(table, action2, 26, groupAny, groupAny, protoAny, 1000, vlanAny, npb2)
	action3 := generateAclAction(27, ACTION_PACKET_BROKERING)
	// acl3 Group: 0 -> 0 Port: 0 Proto: 6 vlan: any
	acl3 := generatePolicyAcl(table, action3, 27, groupAny, groupAny, IPProtocolUDP, 1000, vlanAny, npb3)
	acls = append(acls, acl1, acl2, acl3)
	table.UpdateAcls(acls)
	// 构建预期结果
	basicPolicyData := &PolicyData{}
	basicPolicyData.Merge([]AclAction{action1, action2}, []NpbAction{npb.ReverseTapSide()}, 25, BACKWARD)

	// key1: ip4:1000 -> ip3:1023 tcp
	key1 := generateLookupKey(mac2, mac1, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, false, true)
	policyData := table.LookupPolicyByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key1: ip3:1023 -> ip4:1000 tcp
	key1 = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key1)
	basicPolicyData = &PolicyData{}
	basicPolicyData.Merge([]AclAction{action1, action2}, []NpbAction{npb}, 25)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key2: ip3:1023 -> ip4:1000 udp
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action3, action2}, []NpbAction{npb3, npb2}, 27)
	key2 := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolUDP, 1023, 1000)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key2)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}
}

func TestMultiNpbAction1(t *testing.T) {
	table := generatePolicyTable()
	action := generateAclAction(25, 0)
	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb := ToNpbAction(10, 150, RESOURCE_GROUP_TYPE_DEV, TAPSIDE_SRC, 100)
	// VMA -> ANY SRC
	acl := generatePolicyAcl(table, action, 25, group[1], groupAny, IPProtocolTCP, 0, vlanAny, npb)
	// VMB -> ANY SRC
	acl2 := generatePolicyAcl(table, action, 25, group[2], groupAny, IPProtocolTCP, 0, vlanAny, npb)
	// VMA -> VMB SRC
	acl3 := generatePolicyAcl(table, action, 25, group[1], group[2], IPProtocolTCP, 0, vlanAny, npb)
	// VMB -> VMA SRC
	acl4 := generatePolicyAcl(table, action, 25, group[2], group[1], IPProtocolTCP, 0, vlanAny, npb)
	acls := []*Acl{acl, acl2, acl3, acl4}
	table.UpdateAcls(acls)
	basicPolicyData := &PolicyData{}
	basicPolicyData.Merge([]AclAction{action.AddDirections(BACKWARD)}, []NpbAction{npb.ReverseTapSide()}, 25)

	// key: false:ip1:1000 -> true:ip2:1023 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData := table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip2:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action.AddDirections(BACKWARD)}, []NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1023 -> ture:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip2:1023 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, vlanAny, group1Ip1, ip3, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action}, []NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip1:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, vlanAny, group1Ip1, ip3, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, vlanAny, ip3, group1Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, vlanAny, ip3, group1Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData = table.LookupPolicyByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action.SetDirections(BACKWARD)}, []NpbAction{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip2:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, vlanAny, group2Ip1, ip3, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action}, []NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, vlanAny, group2Ip1, ip3, IPProtocolTCP, 1000, 1023)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, vlanAny, ip3, group2Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, vlanAny, ip3, group2Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	policyData = table.LookupPolicyByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.Merge([]AclAction{action.SetDirections(BACKWARD)}, []NpbAction{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}
}

func TestPolicyDoublePort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1:1000->2:8000 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)

	// 获取查询first结果
	policyData := table.LookupPolicyByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询2-key  2:8000->1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key)
	backward := getBackwardAcl(action)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}
}

func TestPolicySrcPort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1:1000->2:0 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)

	// 获取查询first结果
	policyData := table.LookupPolicyByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询2-key  2:8000->1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key)
	backward := getBackwardAcl(action)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	policyData = table.LookupPolicyByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}
}

func BenchmarkNpbFirstPath(b *testing.B) {
	table := generatePolicyTable()

	action1 := generateAclAction(25, ACTION_PACKET_BROKERING)
	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb1 := ToNpbAction(10, 100, RESOURCE_GROUP_TYPE_IP, TAPSIDE_DST, 100)
	acl1 := generatePolicyAcl(table, action1, 25, groupAny, groupAny, IPProtocolTCP, 1000, vlanAny, npb1)
	acls := []*Acl{acl1}
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := getEndpointData(table, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	}

}

func BenchmarkNpbFastPath(b *testing.B) {
	table := generatePolicyTable()

	action1 := generateAclAction(25, ACTION_PACKET_BROKERING)
	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb1 := ToNpbAction(10, 100, RESOURCE_GROUP_TYPE_IP, TAPSIDE_DST, 100)
	acl1 := generatePolicyAcl(table, action1, 25, groupAny, groupAny, IPProtocolTCP, 1000, vlanAny, npb1)
	acls := []*Acl{acl1}
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1023, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := getEndpointData(table, key)
	table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.policyLabeler.GetPolicyByFastPath(key)
	}
}

func BenchmarkFirstPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable()
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	endpoint := getEndpointData(table, key)
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
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	endpoint := getEndpointData(table, key)
	table.policyLabeler.GetPolicyByFirstPath(endpoint, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.policyLabeler.GetPolicyByFastPath(key)
	}
}

func BenchmarkAcl(b *testing.B) {
	acls := []*Acl{}
	table := generatePolicyTable()
	action := generateAclAction(10, ACTION_PACKET_COUNTING)

	for i := uint16(10000); i < 25000; i += 5000 {
		acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)

		acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(i-5000, i+5000))
		acl.DstPortRange = append(acl.DstPortRange, NewPortRange(i-5000, i+5000))
		for i := 0; i < 100; i++ {
			acl.SrcGroups = append(acl.SrcGroups, uint32(i))
			acl.DstGroups = append(acl.DstGroups, uint32(i))
		}

		acls = append(acls, acl)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.UpdateAcls(acls)
		for _, acl := range acls {
			acl.DstPorts = acl.DstPorts[:0]
			acl.SrcPorts = acl.SrcPorts[:0]
		}
	}
}
