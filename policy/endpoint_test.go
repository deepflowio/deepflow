package policy

import (
	"testing"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

// 平台信息有关测试
func TestGetPlatformData(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	datas := make([]*PlatformData, 0, 2)
	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// epcId:40 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac4 HostIp:launchServer1
	vifData := generatePlatformDataExtension(groupEpc[4], 2, 3, 3, 5, mac4, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	ipInfo2 := generateIpNet(ip2, 125, 24)
	ipInfo3 := generateIpNet(ip1, 126, 32)
	vifData1 := generatePlatformDataExtension(groupEpcAny, 1, 100, 3, 5, mac2, launchServer1)
	vifData1.Ips = append(vifData1.Ips, ipInfo2, ipInfo3)

	datas = append(datas, vifData, vifData1)
	policy.UpdateInterfaceData(datas)

	key := generateLookupKey(mac4, mac2, vlanAny, ip2, ip4, protoAny, 0, 0)
	result, _ := policy.LookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
}

func TestGetPlatformDataAboutArp(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	datas := make([]*PlatformData, 0, 2)

	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// epcId:40 DeviceType:2 DeviceId:3 IfType:3 IfIndex:5 Mac:mac4 HostIp:launchServer1
	vifData := generatePlatformDataExtension(groupEpc[4], 2, 3, 3, 5, mac4, launchServer1)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	datas = append(datas, vifData)
	policy.UpdateInterfaceData(datas)

	key := generateClassicLookupKey(mac4, mac3, ip4, ip3, 0, 0, EthernetTypeARP)
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

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 0, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward, backward}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAllPassPolicy Check failed!")
	}
}

//测试资源组forward策略匹配 direction==1
func TestGroupForwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// srcGroups: 40
	acl1 := generatePolicyAcl(policy, forward, 10, group[4], groupAny, protoAny, 0, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestGroupForwardPassPolicy Check Failed!")
	}
}

//测试资源组backward策略匹配 direction==2
func TestGroupBackwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstGroups: 40
	acl1 := generatePolicyAcl(policy, backward, 10, groupAny, group[4], protoAny, 0, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 30, 30, EthernetTypeARP)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward, backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, vlanAny, ip4, ip2, IPProtocolTCP, 30, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, vlanAny, ip4, ip2, IPProtocolTCP, 0, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, vlanAny, ip4, ip2, IPProtocolTCP, 30, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward, backward}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestSrcDstPortPassPolicy Check Failed!")
	}
}

//测试Vlan策略匹配 acl配置Vlan=30，查询Vlan=30, 查询到Acl
func TestVlanPassPolicy(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 0, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, 30, ip4, ip2, IPProtocolTCP, 30, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward, backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 8000, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, 30, ip4, ip2, IPProtocolTCP, 8000, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, 30, ip4, ip2, IPProtocolTCP, 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{forward, backward}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolUDP, 8000, vlanAny)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 30, ip4, ip2, IPProtocolTCP, 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)

	backward1 := getBackwardAcl(aclAction1)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{aclAction1, backward1}, nil, acl1.Id)
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
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolTCP, 8000, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip4, ip2, IPProtocolTCP, 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)

	backward1 := getBackwardAcl(aclAction1)
	backward2 := getBackwardAcl(aclAction2)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{aclAction2, aclAction1, backward2, backward1}, nil, acl2.Id)
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
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolTCP, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip4, ip2, IPProtocolTCP, 0, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	backward := getBackwardAcl(aclAction2)
	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{aclAction2, backward}, nil, acl2.Id)
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
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolTCP, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, 10, ip4, ip2, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	acl2Backward := getBackwardAcl(aclAction2)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{aclAction2, acl2Backward, aclAction1}, nil, acl2.Id)
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
	acl1 := generatePolicyAcl(policy, aclAction1, 10, groupAny, groupAny, IPProtocolTCP, 8000, vlanAny)
	aclAction2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	acl2 := generatePolicyAcl(policy, aclAction2, 20, groupAny, groupAny, IPProtocolTCP, 0, 10)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, vlanAny, ip4, ip2, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{aclAction1}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy2 Check Failed!")
	}

	_, policyData = getPolicyByFastPath(policy, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanPortAclsPassPolicy2 FastPath Check Failed!")
	}
}

// l2EpcId0=40,L3EpcId0=40,l2Epcid1=0,L3EpcId1=-1的数据正确性
func TestModifyEpcIdPolicy1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	policy.UpdateInterfaceData([]*PlatformData{platformData1})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac4, mac2, vlanAny, ip4, ip2, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpc[4], groupEpc[4], groupEpcAny, groupEpcOther)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy1 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy1 FastPath Check Failed!")
	}
}

// l2EpcId0=40,l3EpcId0=40,l2EpcId1=50,l3EpcId1=50的数据正确性
func TestModifyEpcIdPolicy2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpc[5], 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac4, mac5, vlanAny, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpc[4], groupEpc[4], groupEpc[5], groupEpc[5])
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 FastPath Check Failed!")
	}
}

// l2EpcId0=-1,l3EpcId0=-1,l2Epcid1=0,l3EpcId1=50的数据正确性
func TestModifyEpcIdPolicy3(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpcAny, 3)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpc[5], 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac2, mac1, vlanAny, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpcOther, groupEpcOther, groupEpcAny, groupEpc[5])
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 FastPath Check Failed!")
	}
}

// l2EpcId0=40,l3EpcId0=40,l2EpcId1=0,l3EpcId1=-1的数据正确性
func TestModifyEpcIdPolicy4(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 3)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpcAny, 3)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac5, mac1, vlanAny, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpc[4], groupEpc[4], groupEpcAny, groupEpcOther)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy4 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy4 FastPath Check Failed!")
	}
}

// l3EpcId0=-1, l3EpcId1=-1的数据正确性
func TestModifyEpcIdPolicy5(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpcAny, 4)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpcAny, 4)
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	// l3EpcId0=-1, l3EpcId1=-1, l2EpcId0=0, l2EpcId1=0

	key := generateLookupKey(mac2, mac3, vlanAny, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[1])

	basicData := generateEpcInfo(groupEpcAny, groupEpcOther, groupEpcAny, groupEpcOther)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 FastPath Check Failed!")
	}

	// l3EpcId0=-1, l3EpcId1=-1, l2EpcId0=-1, l2EpcId1=-1
	key.SrcMac = mac4
	key.DstMac = mac5
	key.L2End0 = true

	basicData = generateEpcInfo(groupEpcOther, groupEpcOther, groupEpcOther, groupEpcOther)
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5-2 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5-2 FastPath Check Failed!")
	}
}

// 东西向L3EpcId经过修正后的数据正确性
// 修正IP范围{10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 255.255.255.255/32}
// L3EpcId0=0,L3EpcId1=0 修正后-> L3EpcId0=-1,L3EpcId1=-1
func TestModifyPrivateIp(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	// 192.168.0.0/16
	key := generateLookupKey(mac1, mac2, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	basicData := generateEpcInfo(groupEpc[0], groupEpcOther, groupEpc[0], groupEpcOther)
	data, _ := policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp Check Failed!")
	}
	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp FastPath Check Failed!")
	}
	// 10.0.0.0/8
	key = generateLookupKey(mac2, mac3, vlanAny, ip6, ip8, IPProtocolTCP, 0, 8000)
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp Check Failed!")
	}
	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp FastPath Check Failed!")
	}
	// 172.16.0.0/12
	key = generateLookupKey(mac3, mac4, vlanAny, ip9, ip10, IPProtocolTCP, 0, 8000)
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp Check Failed!")
	}
	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp FastPath Check Failed!")
	}
	// 255.255.255.255/32
	key = generateLookupKey(mac4, mac5, vlanAny, ip11, ip11, IPProtocolTCP, 0, 8000)
	data, _ = policy.LookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp Check Failed!")
	}
	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyPrivateIp FastPath Check Failed!")
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
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[0])

	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[0], l2EndBool[0], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end1 Check Failed!")
	}
}

// L2end0=L2end1=true L3end0=L3end1=false
func TestL2endL3end2(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[1])

	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[0], l2EndBool[1], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end2 Check Failed!")
	}
}

// L2end0=L2end1=false L3end0=true,L3end1=false
func TestL2endL3end3(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[0])

	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end3 Check Failed!")
	}
}

// L2end0=L2end1=true L3end0=true, L3end1=false
func TestL2endL3end4(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[1])

	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[1], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end4 Check Failed!")
	}
}

// L2end0,L2end1 修正
func TestModifyL2end(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[0])
	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[0], l3EndBool[0])
	data := getEndpointData(policy, key)

	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[1])
	basicEndInfo1 := generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[1], l3EndBool[0])
	data1 := getEndpointData(policy, key)

	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestModifyL2end Check Failed!")
	}
	if !checkEndTestResult(t, basicEndInfo1, data1) {
		t.Error("TestModifyL2end Check Failed!")
	}
}

// arp包 ip3-->ip4
// arp包 ip4-->ip3
// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
func TestL2endL3end5(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	// arp包 ip3-->ip4
	key1 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 8000)
	setEthTypeAndOthers(key1, EthernetTypeARP, 64, l2EndBool[0], l2EndBool[0])
	getEndpointData(policy, key1)
	// arp包 ip4-->ip3
	key2 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, protoAny, 0, 8000)
	setEthTypeAndOthers(key2, EthernetTypeARP, 64, l2EndBool[0], l2EndBool[0])
	getEndpointData(policy, key2)

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
	key3 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[0])
	key3.Timestamp = time.Duration(time.Now().UnixNano()) + ARP_VALID_TIME
	data := getEndpointData(policy, key3)
	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key4 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key4, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[0])
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	data = getEndpointData(policy, key4)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}
}

func TestFastpathEndInfo(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	// arp包 ip3-->ip4 ttl=64  L2end0=L2end1=false L3end0=true,L3end1=false
	key1 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 0)
	setEthTypeAndOthers(key1, EthernetTypeARP, 64, l2EndBool[0], l2EndBool[0])
	policy.LookupAllByKey(key1)
	// arp包 ip4-->ip3 ttl=64  L2end0=L2end1=false L3end0=true,L3end1=true
	key2 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, protoAny, 0, 0)
	setEthTypeAndOthers(key2, EthernetTypeARP, 64, l2EndBool[0], l2EndBool[0])
	policy.LookupAllByKey(key2)

	// ip包  ip3-->ip4 ttl=63  L2end0=L2end1=false L3end0=true,L3end1=true
	key3 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, IPProtocolTCP, 50, 60)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[0])
	key3.Timestamp = time.Duration(time.Now().UnixNano()) + ARP_VALID_TIME
	data, _ := policy.LookupAllByKey(key3)
	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=63  L2end0=L2end1=false L3end0=true,L3end1=true
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	data, _ = policy.LookupAllByKey(key3)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
	}
}

func checkEndpointStore(t *testing.T, store *EndpointStore) bool {
	for i := L3_L2_END_FALSE_FALSE; i < L3_L2_END_MAX; i++ {
		for j := L3_L2_END_FALSE_FALSE; j < L3_L2_END_MAX; j++ {
			if store.Datas[i][j].SrcInfo != &store.SrcInfos[i] ||
				store.Datas[i][j].DstInfo != &store.DstInfos[j] {
				t.Error("Result:", store.Datas[i][j])
				t.Error("Expect:", store.SrcInfos[i], store.DstInfos[j])
				return false
			}
		}
	}
	return true
}

func TestFastpathEndpointStore(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	// l2End0=true, l3End0=false, l2End1=false, l3End1=false
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[0])
	policy.LookupAllByKey(key)
	store, _ := policy.policyLabeler.GetPolicyByFastPath(key)
	if !checkEndpointStore(t, store) {
		t.Error("TestFastpathEndpointStore Check Failed!")
	}
}

func TestFastpathL2End(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	// l2End0=true, l3End0=false, l2End1=false, l3End1=false
	key := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[0])
	policy.LookupAllByKey(key)
	endpoint, _ := getPolicyByFastPath(policy, key)
	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[0], l2EndBool[0], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=false, l2End1=true, l3End1=false
	key2 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, protoAny, 0, 0)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[1])
	policy.LookupAllByKey(key2)
	endpoint, _ = getPolicyByFastPath(policy, key2)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[0], l2EndBool[1], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=true, l3End0=false, l2End1=true, l3End1=false
	key3 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 80)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[1])
	endpoint, _ = getPolicyByFastPath(policy, key3)
	basicEndInfo = generateEndInfo(l2EndBool[1], l3EndBool[0], l2EndBool[1], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=false, l2End1=false, l3End1=false
	key4 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 80)
	setEthTypeAndOthers(key4, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[0])
	endpoint, _ = getPolicyByFastPath(policy, key4)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[0], l2EndBool[0], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2End-getPolicyByFastPath Check Failed!")
	}
}

func TestFastpathL2L3End(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	// l2End0=true, l3End0=true, l2End1=true, l3End1=false
	key1 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, protoAny, 80, 0)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[1])
	policy.LookupAllByKey(key1)
	endpoint, _ := getPolicyByFastPath(policy, key1)
	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[1], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=true, l2End1=false, l3End1=false
	key2 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 80)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[0])
	policy.LookupAllByKey(key2)
	endpoint, _ = getPolicyByFastPath(policy, key2)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=true, l3End0=true, l2End1=false, l3End1=false
	key3 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 0, 80)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[0])
	endpoint, _ = getPolicyByFastPath(policy, key3)
	basicEndInfo = generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[0], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=true, l2End1=true, l3End1=false
	key4 := generateLookupKey(mac4, mac3, vlanAny, ip4, ip3, protoAny, 80, 0)
	setEthTypeAndOthers(key4, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[1])
	endpoint, _ = getPolicyByFastPath(policy, key4)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[1], l3EndBool[0])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	generatePlatformData(policy)
	// l2End0=true, l3End0=true, l2End1=true, l3End1=true
	key5 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 80, 0)
	setEthTypeAndOthers(key5, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[1])
	policy.LookupAllByKey(key5)
	endpoint, _ = getPolicyByFastPath(policy, key5)
	basicEndInfo = generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[1], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=true, l2End1=false, l3End1=true
	key6 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 80, 0)
	setEthTypeAndOthers(key6, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[0])
	policy.LookupAllByKey(key6)
	endpoint, _ = getPolicyByFastPath(policy, key6)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=true, l3End0=true, l2End1=false, l3End1=true
	key7 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 80, 0)
	setEthTypeAndOthers(key7, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[0])
	endpoint, _ = getPolicyByFastPath(policy, key7)
	basicEndInfo = generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[0], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}

	// l2End0=false, l3End0=true, l2End1=true, l3End1=true
	key8 := generateLookupKey(mac3, mac4, vlanAny, ip3, ip4, protoAny, 80, 0)
	setEthTypeAndOthers(key8, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[1])
	endpoint, _ = getPolicyByFastPath(policy, key8)
	basicEndInfo = generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[1], l3EndBool[1])
	if !checkEndTestResult(t, basicEndInfo, endpoint) {
		t.Error("TestFastpathL2L3End-getPolicyByFastPath Check Failed!")
	}
}

func TestAnonymousGroupData(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	generatePlatformData(policy)
	ipGroup1 := generateIpGroup(group[1], 0, ipGroup6IpNet1)
	ipGroup1.Type = ANONYMOUS_IP
	ipGroup2 := generateIpGroup(group[2], 0, ipGroup6IpNet2)
	ipGroup2.Type = ANONYMOUS_IP
	ipGroups := make([]*IpGroupData, 0, 2)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2)
	policy.UpdateIpGroupData(ipGroups)

	key := generateClassicLookupKey(mac1, mac2, ipGroup6Ip1, ipGroup6Ip2, 0, 0, EthernetTypeIPv4)
	data := getEndpointData(policy, key)
	if data.SrcInfo.GroupIds[0] != group[1]+1e9 ||
		data.DstInfo.GroupIds[0] != group[2]+1e9 {
		t.Error("TestAnonymousGroupData Check Failed!")
		t.Log(data.SrcInfo, "\n")
		t.Log(data.DstInfo, "\n")
	}
	data, _ = policy.LookupAllByKey(key)
	if len(data.SrcInfo.GroupIds) != 0 ||
		len(data.DstInfo.GroupIds) != 0 {
		t.Error("TestAnonymousGroupData Check Failed!")
		t.Log(data.SrcInfo, "\n")
		t.Log(data.DstInfo, "\n")
	}
}

func TestIpNetmaskGroup(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	ipGroup1 := generateIpGroup(group[11], groupEpc[0], ipNet10, ipNet11)
	ipGroup2 := generateIpGroup(group[12], groupEpc[0], ipNet12)
	ipGroup3 := generateIpGroup(group[13], groupEpc[0], ipNet13)
	ipGroup4 := generateIpGroup(group[14], groupEpc[0], ipNet14)
	ipGroup5 := generateIpGroup(group[15], groupEpc[0], ipNet15)
	ipGroups := make([]*IpGroupData, 0, 5)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3, ipGroup4, ipGroup5)
	policy.UpdateIpGroupData(ipGroups)
	srcIp := NewIPFromString("10.90.1.12").Int()
	dstIp := NewIPFromString("10.90.9.123").Int()
	key := generateLookupKey(mac1, mac2, vlanAny, srcIp, dstIp, IPProtocolTCP, 50, 60)
	data, _ := policy.LookupAllByKey(key)
	if len(data.SrcInfo.GroupIds) != 4 ||
		len(data.DstInfo.GroupIds) != 5 {
		t.Error("TestIpNetmaskGroup Check Failed!")
	}
}

func TestIpNetmaskGroup1(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	ipGroup1 := generateIpGroup(group[11], groupEpc[0], ipNet10, ipNet11)
	ipGroup2 := generateIpGroup(group[12], groupEpc[0], ipNet12)
	ipGroup3 := generateIpGroup(group[13], groupEpc[0], ipNet13)
	ipGroup4 := generateIpGroup(group[14], groupEpc[0], ipNet14)
	ipGroup5 := generateIpGroup(group[15], groupEpc[0], ipNet15)
	ipGroups := make([]*IpGroupData, 0, 5)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3, ipGroup4, ipGroup5)
	policy.UpdateIpGroupData(ipGroups)
	srcIp := NewIPFromString("10.90.1.12").Int()
	dstIp := NewIPFromString("10.90.9.123").Int()
	ipNet := generateIpNet(srcIp, 123, 32)
	data1 := generatePlatformDataWithGroupId(groupEpc[1], group[1], group1Mac, ipNet)
	policy.UpdateInterfaceData([]*PlatformData{data1})
	key := generateLookupKey(group1Mac, mac2, vlanAny, srcIp, dstIp, IPProtocolTCP, 50, 60)
	data, _ := policy.LookupAllByKey(key)
	if len(data.SrcInfo.GroupIds) != 5 ||
		len(data.DstInfo.GroupIds) != 5 {
		t.Error("TestIpNetmaskGroup Check Failed!")
	}
}

func BenchmarkGetEndpointData(b *testing.B) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	platformData1 := generatePlatformDataByParam(group1Ip1, group1Mac, groupEpc[1], 4)
	platformData1.GroupIds = append(platformData1.GroupIds, group[1])
	platformData2 := generatePlatformDataByParam(group2Ip1, group2Mac, groupEpc[2], 4)
	platformData2.GroupIds = append(platformData2.GroupIds, group[2])
	policy.UpdateInterfaceData([]*PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getEndpointData(policy, key)
	}
}

func BenchmarkGetDataByIp(b *testing.B) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)
	ip1 := generateIpNet(testIp1, 100, 32)
	data1 := generatePlatformDataWithGroupId(groupEpc[1], group[1], testMac1, ip1)
	ip2 := generateIpNet(testIp2, 200, 24)
	data2 := generatePlatformDataWithGroupId(groupEpc[2], group[2], testMac2, ip2)
	ip3 := generateIpNet(testIp3, 300, 16)
	data3 := generatePlatformDataWithGroupId(groupEpc[3], group[3], testMac3, ip3)
	ip4 := generateIpNet(testIp4, 300, 8)
	data4 := generatePlatformDataWithGroupId(groupEpc[4], group[4], testMac4, ip4)
	policy.UpdateInterfaceData([]*PlatformData{data1, data2, data3, data4})
	for i := 0; i < b.N; i++ {
		policy.cloudPlatformLabeler.GetDataByIp(queryIp)
	}
}
