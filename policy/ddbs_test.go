package policy

import (
	"testing"

	. "github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func TestDdbsSimple(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
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
		t.Error("TestDdbsSimple Check Failed!")
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
		t.Error("TestDdbsSimple 2-key Check Failed!")
	}

	// 构建无效查询3-key  2:0->1:8000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// key不匹配，返回无效policy
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsSimple 3-key Check Failed!")
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
		t.Error("TestDdbsSimple 4-key Check Failed!")
	}
}

func BenchmarkDdbsFirstPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		endpoint := getEndpointData(table, key)
		table.operator.GetPolicyByFirstPath(endpoint, key)
	}
}

func BenchmarkDdbsFirstPathWithMultiGroup(b *testing.B) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)

	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acls = append(acls, acl)
	srcGroups := []uint32{group[1]}
	dstGroups := []uint32{group[2]}
	for i := group[2]; i <= 100; i += 10 {
		acl := generatePolicyAcl(table, action, ACLID(i), uint32(i), uint32(i+10), IPProtocolTCP, 0, vlanAny)
		acls = append(acls, acl)
		srcGroups = append(srcGroups, i+10)
		dstGroups = append(dstGroups, i+10)
	}
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoint := getEndpointData(table, key)
		endpoint.SrcInfo.GroupIds = srcGroups
		endpoint.DstInfo.GroupIds = dstGroups
		table.operator.GetPolicyByFirstPath(endpoint, key)
	}
}

func TestDdbsPolicyEpcPolicy(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
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

func TestDdbsPolicyEpcIpGroup(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[16], groupAny, IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group1Ip3, IPProtocolTCP, 0, 8000)
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyEpcIpGroup Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group2Ip2, group1Ip3, IPProtocolTCP, 0, 8000)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPolicyEpcIpGroup Check Failed!")
	}
}

func TestDdbsFlowVlanAcls(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
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

func TestDdbsIpGroupPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
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

func TestDdbsVlanProtoPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
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
	basicPolicyData.Merge([]AclAction{action2, action3}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl Check Failed!")
	}
	// 获取fastpath查询结果
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestVlanProtoPortAcl FastPath Check Failed!")
	}

	acls = []*Acl{}
	table = generatePolicyTable(DDBS)
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

func TestDdbsResourceGroupPolicy(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
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
	table = generatePolicyTable(DDBS)
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
	basicPolicyData.Merge([]AclAction{action2, action3}, nil, acl2.Id)
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
	basicPolicyData.Merge([]AclAction{action2, action3}, nil, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 6-key FastPath Check Failed!")
	}
}

func TestDdbsSrcDevGroupDstIpGroupPolicy(t *testing.T) {
	table := generatePolicyTable(DDBS)
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
	basicPolicyData1.Merge([]AclAction{action1, action2, backward1}, nil, acl1.Id) // 可以匹配backward1
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group3)group3Ip2 -> (group3/ipGroup6)group3Ip1
	key2 := generateLookupKey(group3Mac1, ipGroup6Mac1, vlanAny, group3Ip2, group3Ip1, IPProtocolUDP, 0, 0)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	// 不匹配backward2
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]AclAction{action1, action2}, nil, acl1.Id)
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
	basicPolicyData3.Merge([]AclAction{action1, action2}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key4 := generateLookupKey(group4Mac1, group5Mac1, 10, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key4)
	// 源端匹配group4不匹配group3，目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key4)
	basicPolicyData4 := new(PolicyData)
	basicPolicyData4.Merge([]AclAction{action1, action4}, nil, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key5 := generateLookupKey(group4Mac1, macAny, 10, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key5)
	// 源端匹配group4不匹配group3,目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key5)
	basicPolicyData5 := new(PolicyData)
	basicPolicyData5.Merge([]AclAction{action1, action4}, nil, acl1.Id)
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

func TestDdbsFirstPathVsFastPath(t *testing.T) {
	table := generatePolicyTable(DDBS)
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
		t.Error("key1 FirstPath Check Failed! ", result)
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

func TestDdbsEndpointDataDirection(t *testing.T) {
	table := generatePolicyTable(DDBS)
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
	basicPolicyData1.Merge([]AclAction{action1, action2}, nil, acl1.Id)
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
	basicPolicyData2.Merge([]AclAction{backward1, backward2}, nil, acl1.Id)
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

func TestDdbsNpbAction(t *testing.T) {
	table := generatePolicyTable(DDBS)
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
	basicPolicyData.MergeNpbAction([]NpbAction{npb.ReverseTapSide()}, 25, BACKWARD)

	// key1: ip4:1000 -> ip3:1023 tcp
	key1 := generateLookupKey(mac2, mac1, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, false, true)
	_, policyData := table.LookupAllByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key1: ip3:1023 -> ip4:1000 tcp
	key1 = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key1)
	basicPolicyData = &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb}, 25)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key2: ip3:1023 -> ip4:1000 udp
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb2, npb3}, 26)
	key2 := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolUDP, 1023, 1000, NPB)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.LookupAllByKey(key2)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}
}

func TestDdbsMultiNpbAction1(t *testing.T) {
	table := generatePolicyTable(DDBS)
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
	basicPolicyData.NpbActions = make([]NpbAction, 0, 1)
	basicPolicyData.MergeNpbAction([]NpbAction{}, 25)

	// key: false:ip1:1000 -> true:ip2:1023 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData := table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
		t.Error(cap(basicPolicyData.AclActions), cap(basicPolicyData.NpbActions), cap(basicPolicyData.AclGidBitmaps))
		t.Error(cap(policyData.AclActions), cap(policyData.NpbActions), cap(policyData.AclGidBitmaps))
	}

	// key: true:ip2:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1023 -> ture:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip2:1023 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, vlanAny, group1Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip1:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, vlanAny, group1Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, vlanAny, ip3, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, vlanAny, ip3, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.LookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip2:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, vlanAny, group2Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, vlanAny, group2Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, vlanAny, ip3, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, vlanAny, ip3, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.LookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbAction{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}
}

func TestDdbsNpbActionDedup(t *testing.T) {
	table := generatePolicyTable(DDBS)
	npb1 := ToNpbAction(10, 100, RESOURCE_GROUP_TYPE_DEV, TAPSIDE_SRC, 100)
	npb2 := ToNpbAction(10, 150, RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 0)
	npb3 := ToNpbAction(10, 100, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 200)
	npb4 := ToNpbAction(20, 100, RESOURCE_GROUP_TYPE_DEV|RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 100)
	// VM段-A -> ANY, DEV-group2 -> ANY
	action1 := generateAclAction(25, ACTION_PACKET_BROKERING)
	acl1 := generatePolicyAcl(table, action1, 25, group[2], groupAny, IPProtocolTCP, 0, vlanAny, npb1)
	// IP段-A -> ANY, IP-group3 -> ANY
	action2 := generateAclAction(26, ACTION_PACKET_BROKERING)
	acl2 := generatePolicyAcl(table, action2, 26, group[3], groupAny, IPProtocolTCP, 0, vlanAny, npb2)
	acls := []*Acl{acl1, acl2}
	table.UpdateAcls(acls)

	basicPolicyData := new(PolicyData)
	basicPolicyData.MergeNpbAction([]NpbAction{npb1, npb2}, 25)
	// key: true:(DEV-group2/IP-group3)group2Ip1:1000 -> true:(DEV-group4/IP-group6)group4Ip1:1023 tcp
	key := generateLookupKey(group2Mac, group4Mac1, vlanAny, group2Ip1, group4Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := modifyEndpointDataL3End(table, key, l3EndBool[1], l3EndBool[1])
	policyData := getPolicyByFirstPath(table, endpoint, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionDedup Check Failed!")
	}

	// IP段-B -> VMA, IP-group6 -> DEV-group2
	action3 := generateAclAction(27, ACTION_PACKET_BROKERING)
	acl3 := generatePolicyAcl(table, action3, 27, group[6], group[2], IPProtocolTCP, 0, vlanAny, npb3)
	// VMB -> IP段-A, DEV-group4 -> IP-group3
	action4 := generateAclAction(28, ACTION_PACKET_BROKERING)
	acl4 := generatePolicyAcl(table, action4, 28, group[4], group[3], IPProtocolTCP, 0, vlanAny, npb4)

	acls = append(acls, acl3, acl4)
	table.UpdateAcls(acls)

	basicPolicyData = new(PolicyData)
	basicPolicyData.MergeNpbAction([]NpbAction{npb1, npb2, npb4.ReverseTapSide(), npb3.ReverseTapSide()}, acl1.Id)
	basicPolicyData.FormatNpbAction()
	// key不变，acl改变
	policyData = getPolicyByFirstPath(table, endpoint, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionDedup Check Failed!")
	}

	// IP段-A -> IP段-B, IP-group3 -> IP-group6
	npb5 := ToNpbAction(20, 150, RESOURCE_GROUP_TYPE_IP, TAPSIDE_SRC, 100)
	action5 := generateAclAction(29, ACTION_PACKET_BROKERING)
	acl5 := generatePolicyAcl(table, action5, 29, group[6], group[6], IPProtocolTCP, 0, vlanAny, npb5)
	acls = []*Acl{acl5}
	table.UpdateAcls(acls)

	basicPolicyData = new(PolicyData)
	basicPolicyData.MergeNpbAction([]NpbAction{npb5, npb5.ReverseTapSide()}, acl5.Id)
	basicPolicyData.FormatNpbAction()
	// key: true:(IP-group6)ipGroup6Ip2:1000 -> true:(IP-group6)ipGroup6Ip4:1023 tcp
	key = generateLookupKey(ipGroup6Mac1, ipGroup6Mac1, vlanAny, ipGroup6Ip2, ipGroup6Ip4, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint = modifyEndpointDataL3End(table, key, l3EndBool[1], l3EndBool[1])
	policyData = getPolicyByFirstPath(table, endpoint, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionDedup Check Failed!")
	}
}

func TestDdbsPolicyDoublePort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
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
	_, policyData := table.LookupAllByKey(key)
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
	_, policyData = table.LookupAllByKey(key)
	backward := getBackwardAcl(action)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}
}

func TestDdbsPolicySrcPort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
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
	_, policyData := table.LookupAllByKey(key)
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
	_, policyData = table.LookupAllByKey(key)
	backward := getBackwardAcl(action)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{backward}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}
}

func TestDdbsAclGidBitmap(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:0 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(10)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData := table.LookupAllByKey(key)
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(0).SetDstMapBits(0)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
}

func TestDdbsAclGidBitmapMultiGroup(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:0 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(10)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := getEndpointData(table, key)

	// endpoint中匹配策略的资源组和不匹配策略的资源组相交叉
	endpoint.SrcInfo.GroupIds = append(endpoint.SrcInfo.GroupIds[:0], group[1], 100, group[1])
	endpoint.DstInfo.GroupIds = append(endpoint.DstInfo.GroupIds[:0], group[2], 200, group[2])
	policyData := getPolicyByFirstPath(table, endpoint, key)
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(0).SetDstMapBits(0)
	aclGidBitmap = aclGidBitmap.SetSrcMapBits(2).SetDstMapBits(2)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}

	// endpoint中匹配策略的资源组在不匹配策略的资源组的后面
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	endpoint.SrcInfo.GroupIds = append(endpoint.SrcInfo.GroupIds[:0], 100, group[1])
	endpoint.DstInfo.GroupIds = append(endpoint.DstInfo.GroupIds[:0], 200, group[2])
	policyData = getPolicyByFirstPath(table, endpoint, key)

	aclGidBitmap = AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(1).SetDstMapBits(1)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
}

func TestDdbsAclGidBitmapAnonymousGroupIds(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:0 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(10)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := getEndpointData(table, key)

	// endpoint中匹配策略的资源组和不匹配策略的资源组相交叉
	endpoint.SrcInfo.GroupIds = append(endpoint.SrcInfo.GroupIds[:0], group[1], 100, 300, group[1])
	endpoint.DstInfo.GroupIds = append(endpoint.DstInfo.GroupIds[:0], group[2], 200, 300, group[2])
	table.cloudPlatformLabeler.ipGroup.anonymousGroupIds[300] = true
	policyData := getPolicyByFirstPath(table, endpoint, key)
	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(0).SetDstMapBits(0)
	aclGidbitmap = aclGidbitmap.SetSrcMapBits(2).SetDstMapBits(2)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidbitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
}

func TestDdbsAclGidBitmapFirstPathVsFastPath(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:0 tcp
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(10)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1000, 1000))
	acl1 := generatePolicyAcl(table, action, 20, group[2], group[1], IPProtocolTCP, 0, vlanAny)
	acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(8000, 8000))
	acls = append(acls, acl, acl1)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key1 := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, true, true)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(0).SetDstMapBits(0)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].AddDirections(BACKWARD)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPath FirstPath Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key1)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPath FastPath Check Failed!")
	}

	key2 := generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, true, true)
	basicPolicyData.ACLID = 20
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPath FirstPath Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key2)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPath FastPath Check Failed!")
	}
}

func TestDdbsAclGidBitmapFirstPathVsFastPathByVlan(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(10)
	acl1 := generatePolicyAcl(table, action, 10, group[1], group[2], protoAny, 0, vlan1)
	acl2 := generatePolicyAcl(table, action, 20, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)
	// vlan1策略正向
	key1 := generateLookupKey(group1Mac, group2Mac, vlan1, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, true, true)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapBits(0).SetDstMapBits(0)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl1.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FirstPath Check Failed!")
	}
	key1.SrcAllGroupIds = nil
	key1.DstAllGroupIds = nil
	_, policyData = getPolicyByFastPath(table, key1)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FastPath Check Failed!")
	}
	// vlan1策略反向
	key2 := generateLookupKey(group2Mac, group1Mac, vlan1, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, true, true)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetDirections(BACKWARD)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FirstPath Check Failed!")
	}
	key2.SrcAllGroupIds = nil
	key2.DstAllGroupIds = nil
	_, policyData = getPolicyByFastPath(table, key2)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FastPath Check Failed!")
	}
	// vlanAny策略正向
	key3 := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 64, true, true)
	result = getEndpointData(table, key3)
	policyData = getPolicyByFirstPath(table, result, key3)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetDirections(FORWARD)
	basicPolicyData.ACLID = 20
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FirstPath Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key3)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FastPath Check Failed!")
	}
	// vlanAny策略反向
	key4 := generateLookupKey(group2Mac, group1Mac, vlanAny, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key3, EthernetTypeIPv4, 64, true, true)
	result = getEndpointData(table, key4)
	policyData = getPolicyByFirstPath(table, result, key4)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetDirections(BACKWARD)
	basicPolicyData.ACLID = 20
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FirstPath Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key4)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmapFirstPathVsFastPathByVlan FastPath Check Failed!")
	}
}

func TestDdbsAclGidBitmapGroup48(t *testing.T) {
	acls := []*Acl{}
	table := NewPolicyTable(1, 1024, false, DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action = action.SetACLGID(100)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	for i := 102; i < 150; i++ {
		acl.SrcGroups = append(acl.SrcGroups, uint32(i))
		acl.DstGroups = append(acl.DstGroups, uint32(i))
	}
	acls = append(acls, acl)
	ipGroups := make([]*IpGroupData, 0, 48)
	// internet资源组
	for i := 102; i < 150; i++ {
		ipGroups = append(ipGroups, generateIpGroup(uint32(i), 0, "0.0.0.0/0"))
	}
	table.UpdateIpGroupData(ipGroups)
	table.UpdateAclData(acls, false)
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, testIp4, queryIp, IPProtocolTCP, 0, 0)
	_, policyData := table.LookupAllByKey(key)
	aclGidBitmap0 := AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap1 := AclGidBitmap(0).SetSrcAndDstFlag()
	for i := 0; i < 24; i++ {
		aclGidBitmap0 = aclGidBitmap0.SetSrcMapBits(uint32(i)).SetDstMapBits(uint32(i))
	}
	aclGidBitmap1 = aclGidBitmap1.SetSrcMapOffset(24).SetDstMapOffset(24)
	for i := 24; i < 48; i++ {
		aclGidBitmap1 = aclGidBitmap1.SetSrcMapBits(uint32(i)).SetDstMapBits(uint32(i))
	}
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].AddDirections(BACKWARD)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap0, aclGidBitmap1)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsAclGidBitmapGroup48 Check Failed!")
	}
}

func TestDdbsTapType(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000 tapType=0|1
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action2 := generateAclAction(100, ACTION_FLOW_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acl.Type = 1
	acl2 := generatePolicyAcl(table, action2, 100, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	acl2.Type = 0
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp tapType=1
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	key.Tap = GetTapType(0x10001)

	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action, action2}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsTapType Check Failed!")
	}

	// 构建查询1-key  1:0->2:8000 tcp tapType=2
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	key.Tap = GetTapType(0x10002)

	// 获取查询first结果
	_, policyData = table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action2}, nil, acl2.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsTapType Check Failed!")
	}
}

func TestDdbsAclGidBitmapByDesignationAcls(t *testing.T) {
	table := NewPolicyTable(1, 1024, false, DDBS)
	action1 := generateAclAction(10, ACTION_PACKET_COUNTING)
	action1 = action1.SetACLGID(100)
	action2 := generateAclAction(20, ACTION_PACKET_COUNTING)
	action2 = action2.SetACLGID(200)
	action3 := generateAclAction(30, ACTION_PACKET_COUNTING)
	action3 = action3.SetACLGID(300)
	action4 := generateAclAction(30, ACTION_PACKET_COUNTING)
	action4 = action4.SetACLGID(400)
	// 10->20
	acl1 := generatePolicyAcl(table, action1, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	// any->20
	acl2 := generatePolicyAcl(table, action2, 20, groupAny, group[2], IPProtocolTCP, 0, vlanAny)
	// 10->any
	acl3 := generatePolicyAcl(table, action3, 30, group[1], groupAny, IPProtocolTCP, 0, vlanAny)
	// any->any
	acl4 := generatePolicyAcl(table, action4, 40, groupAny, groupAny, IPProtocolTCP, 0, vlanAny)
	ipGroups := make([]*IpGroupData, 0, 100)
	ipGroups = append(ipGroups, generateIpGroup(group[1], 0, group1Ip1Net))
	ipGroups = append(ipGroups, generateIpGroup(group[2], 0, group2Ip1Net))
	table.UpdateIpGroupData(ipGroups)
	acls := []*Acl{}
	acls = append(acls, acl1, acl2, acl3, acl4)
	table.UpdateAcls(acls)
	// group1Ip1 -> group2Ip1
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 0)
	_, policyData := table.LookupAllByKey(key)
	aclGidBitmap1 := AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap1 = aclGidBitmap1.SetSrcMapOffset(0).SetSrcMapBits(0)
	aclGidBitmap1 = aclGidBitmap1.SetDstMapOffset(0).SetDstMapBits(0)
	aclGidBitmap2 := AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap2 = aclGidBitmap2.SetDstMapOffset(0).SetDstMapBits(0)
	aclGidBitmap3 := AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap3 = aclGidBitmap3.SetSrcMapOffset(0).SetSrcMapBits(0)

	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action1, action2, action3, action4}, nil, acl1.Id)
	basicPolicyData.AclActions[3] = basicPolicyData.AclActions[3].AddDirections(BACKWARD)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclActions[1] = basicPolicyData.AclActions[1].SetAclGidBitmapOffset(1).SetAclGidBitmapCount(1)
	basicPolicyData.AclActions[2] = basicPolicyData.AclActions[2].SetAclGidBitmapOffset(2).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap1, aclGidBitmap2, aclGidBitmap3)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
	// group1Ip1 -> group3Ip1
	key1 := generateLookupKey(group1Mac, group3Mac1, vlanAny, group1Ip1, group3Ip1, IPProtocolTCP, 0, 0)
	_, policyData = table.LookupAllByKey(key1)
	aclGidBitmap1 = AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap1 = aclGidBitmap1.SetSrcMapOffset(0).SetSrcMapBits(0)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action3, action4}, nil, acl3.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclActions[1] = basicPolicyData.AclActions[1].AddDirections(BACKWARD)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap1)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
	// group2Ip1 -> group3Ip1
	key2 := generateLookupKey(group2Mac, group3Mac1, vlanAny, group2Ip1, group3Ip1, IPProtocolTCP, 0, 0)
	_, policyData = table.LookupAllByKey(key2)
	aclGidBitmap1 = AclGidBitmap(0).SetSrcAndDstFlag()
	aclGidBitmap1 = aclGidBitmap1.SetSrcMapOffset(0).SetSrcMapBits(0)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]AclAction{action4, action2}, nil, acl4.Id)
	basicPolicyData.AclActions[0] = basicPolicyData.AclActions[0].AddDirections(BACKWARD)
	basicPolicyData.AclActions[1] = basicPolicyData.AclActions[1].SetDirections(BACKWARD)
	basicPolicyData.AclActions[1] = basicPolicyData.AclActions[1].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	basicPolicyData.AclGidBitmaps = append(basicPolicyData.AclGidBitmaps, aclGidBitmap1)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclGidBitmap Check Failed!")
	}
}

func TestDdbsInternet(t *testing.T) {
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acls := []*Acl{}
	acl := generatePolicyAcl(table, action, 10, group[1], uint32(GROUP_INTERNET&0xffff), IPProtocolTCP, 8000, vlanAny)
	acls = append(acls, acl)
	ipGroups := make([]*IpGroupData, 0, 1)
	ipGroups = append(ipGroups, generateIpGroup(GROUP_INTERNET&0xffff, EPC_FROM_INTERNET, "0.0.0.0/0")) // internet
	table.UpdateIpGroupData(ipGroups)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp, 这里dstMac使用一个不在Platform中的，避免获取到资源组
	key := generateLookupKey(group1Mac, 100, vlanAny, group1Ip1, queryIp, IPProtocolTCP, 0, 8000)
	// 获取查询first结果
	_, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsInternet Check Failed!")
	}
}

func TestDdbsPolicyIpv6(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	action2 := generateAclAction(20, ACTION_PACKET_BROKERING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000, vlanAny)
	// ip: 0.0.0.0/32, epc: 0
	acl2 := generatePolicyAcl(table, action2, 20, group[17], groupAny, protoAny, 0, vlanAny)
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey6(group1Mac, group2Mac, vlanAny, ip12, ip13, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	endpoints, policyData := table.LookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) || endpoints.SrcInfo.L3End != true || endpoints.DstInfo.L3End != true {
		t.Error(endpoints)
		t.Error("TestDdbsPolicyIpv6 Check Failed!")
	}
}

func TestDdbsProtocol(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolGRE, 0, vlanAny)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 生成匹配策略的key
	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolGRE, 0, 0)

	_, policyData := table.LookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]AclAction{action}, nil, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestProtocol Check Failed!")
	}

	// 通过fastPath查询
	_, policyData = table.operator.GetPolicyByFastPath(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestProtocol Check Failed!")
	}

	// 生成不匹配策略的key
	key = generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolUDP, 0, 0)

	_, policyData = table.LookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestProtocol Check Failed!")
	}
}

func TestDdbsPeerConnection(t *testing.T) {
	table := generatePolicyTable(DDBS)
	// group2Ip1对应EPC有两个分别为12和20，若没有对等连接查询，会查询到12
	key := generateLookupKey(group1Mac, mac3, vlanAny, group1Ip1, group2Ip1, IPProtocolUDP, 0, 0)
	endpoints, _ := table.LookupAllByKey(key)
	if endpoints.DstInfo.L3EpcId != 20 {
		t.Error(endpoints)
		t.Error("TestDdbsPeerConnection Check Failed!")
	}
}

func BenchmarkDdbsAcl(b *testing.B) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)

	for i := uint16(1); i <= 1000; i++ {
		acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)

		acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1+10*i, 100+10*i))
		acl.DstPortRange = append(acl.DstPortRange, NewPortRange(30000+10*i, 30100+10*i))
		acl.SrcGroups = acl.SrcGroups[:0]
		acl.DstGroups = acl.DstGroups[:0]
		for j := 100; j < 200; j++ {
			acl.SrcGroups = append(acl.SrcGroups, uint32(j))
			acl.DstGroups = append(acl.DstGroups, uint32(j))
		}
		acl.Action[0].SetACLGID(10)

		acls = append(acls, acl)
	}
	b.ResetTimer()
	table.UpdateAcls(acls)
}
