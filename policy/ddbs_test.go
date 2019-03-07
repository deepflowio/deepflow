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
	endpoint := getEndpointData(table, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.operator.GetPolicyByFirstPath(endpoint, key)
		key.SrcGroupIds = nil
		key.DstGroupIds = nil
		key.SrcAllGroupIds = nil
		key.DstAllGroupIds = nil
	}
}

func BenchmarkDdbsFirstPathWithMultiGroup(b *testing.B) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := generateAclAction(10, ACTION_PACKET_COUNTING)

	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0, vlanAny)
	acl1 := generatePolicyAcl(table, action, 11, uint32(300), uint32(1000), IPProtocolTCP, 0, vlanAny)
	acl2 := generatePolicyAcl(table, action, 12, uint32(400), uint32(1000), IPProtocolTCP, 0, vlanAny)
	acl3 := generatePolicyAcl(table, action, 13, uint32(500), uint32(1000), IPProtocolTCP, 0, vlanAny)

	acls = append(acls, acl, acl1, acl2, acl3)
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, vlanAny, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	endpoint := getEndpointData(table, key)
	endpoint.SrcInfo.GroupIds = append(acl.SrcGroups, 300, 400, 500)
	endpoint.DstInfo.GroupIds = append(acl.DstGroups, 300, 400, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.operator.GetPolicyByFirstPath(endpoint, key)
	}
}
