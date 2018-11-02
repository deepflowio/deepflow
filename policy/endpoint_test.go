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

	_, policyData = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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

	data, _ = getPolicyByFastPath(policy, key)
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
	data := getEndpointData(policy, key)
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
	data := getEndpointData(policy, key)
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
	data := getEndpointData(policy, key)
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
	data := getEndpointData(policy, key)
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
	data := getEndpointData(policy, key1)
	basicEndInfo := generateEndInfo(false, true, false, false)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key2 := generateLookupKey(mac4, mac3, 0, ip4, ip3, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, false, false)
	basicEndInfo = generateEndInfo(false, true, false, true)
	data = getEndpointData(policy, key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=false,L3end1=true
	key2.Ttl = 63
	basicEndInfo.L3End0 = false
	data = getEndpointData(policy, key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=false
	key3 := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 0, 8000)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 63, false, false)
	data = getEndpointData(policy, key3)
	basicEndInfo = generateEndInfo(false, true, false, false)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// arp包 ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key4 := generateLookupKey(mac4, mac3, 0, ip4, ip3, 0, 0, 8000)
	setEthTypeAndOthers(key4, EthernetTypeARP, 64, false, false)
	basicEndInfo = generateEndInfo(false, true, false, true)
	data = getEndpointData(policy, key4)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
	data = getEndpointData(policy, key3)
	basicEndInfo = generateEndInfo(false, true, false, true)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end5 Check Failed!")
	}
}

func TestFastpathEndInfo(t *testing.T) {
	policy := NewPolicyTable(ACTION_PACKET_COUNTING, 1, 1024, false)

	// arp包 ip3-->ip4 ttl=64  L2end=L2end1=false L3end0=true,L3end1=false
	key1 := generateLookupKey(mac3, mac4, 0, ip3, ip4, 0, 0, 0)
	setEthTypeAndOthers(key1, EthernetTypeARP, 64, false, false)
	data, _ := policy.LookupAllByKey(key1)
	basicEndInfo := generateEndInfo(false, true, false, false)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=false,L3end1=true
	key2 := generateLookupKey(mac4, mac3, 0, ip4, ip3, uint8(IPProtocolTCP), 60, 50)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 63, false, false)
	basicEndInfo = generateEndInfo(false, false, false, true)
	data, _ = policy.LookupAllByKey(key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
		return
	}

	// arp包 ip4-->ip3 ttl=64  L2end=L2end1=false L3end0=true,L3end1=true
	key3 := generateLookupKey(mac4, mac3, 0, ip4, ip3, 0, 0, 0)
	setEthTypeAndOthers(key3, EthernetTypeARP, 64, false, false)
	basicEndInfo = generateEndInfo(false, true, false, true)
	data, _ = policy.LookupAllByKey(key3)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
	}

	// ip包  ip3-->ip4 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
	key4 := generateLookupKey(mac3, mac4, 0, ip3, ip4, uint8(IPProtocolTCP), 50, 60)
	setEthTypeAndOthers(key4, EthernetTypeIPv4, 63, false, false)
	data, _ = policy.LookupAllByKey(key4)
	basicEndInfo = generateEndInfo(false, true, false, true)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
	}

	// ip包  ip4-->ip3 ttl=63  L2end=L2end1=false L3end0=true,L3end1=true
	basicEndInfo = generateEndInfo(false, true, false, true)
	data, _ = policy.LookupAllByKey(key2)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestFastpathEndInfo Check Failed!")
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
		getEndpointData(policy, key)
	}
}
