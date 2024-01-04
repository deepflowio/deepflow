/*
 * Copyright (c) 2024 Yunshan Networks
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
	"testing"

	. "github.com/google/gopacket/layers"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

func TestDdbsSimple(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsSimple Check Failed!")
	}

	// 构建查询2-key  2:8000->1:0 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 0)
	// key和acl方向相反，构建反向的action
	backward := action.ReverseTapSide()
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl.Id)
	// 查询结果和预期结果比较
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsSimple 2-key Check Failed!")
	}

	// 构建无效查询3-key  2:0->1:8000 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = table.lookupAllByKey(key)
	basicPolicyData = INVALID_POLICY_DATA
	// key不匹配，返回无效policy
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsSimple 3-key Check Failed!")
	}

	// 测试同样的key, 匹配两条action
	action2 := toNpbAction(12, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 12, group[1], group[2], IPProtocolTCP, 8000)
	acls = append(acls, acl2)
	table.UpdateAcls(acls)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2, action}, acl2.Id)

	// 4-key
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsSimple 4-key Check Failed!")
	}
}

func BenchmarkDdbsFirstPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, 0, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	policy := new(PolicyData)
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		endpoint := getEndpointData(table, key)
		table.operator.GetPolicyByFirstPath(key, policy, endpoint)
	}
}

func TestDdbsPolicyEpcPolicy(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], groupAny, IPProtocolTCP, 8000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group1Mac2, group1Ip1, group1Ip3, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyEpcPolicy Check Failed!")
	}

	_, policyData = getPolicyByFastPath(table, key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyEpcPolicy FastPath Check Failed!")
	}

	backward := action.ReverseTapSide()
	key = generateLookupKey(group1Mac2, group1Mac, group1Ip3, group1Ip1, IPProtocolTCP, 8000, 0)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl.Id)
	_, policyData = getPolicyByFastPath(table, key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy Check Failed!")
	}

	key = generateLookupKey(group1Mac2, group1Mac, group1Ip3, group1Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = getPolicyByFastPath(table, key)
	basicPolicyData = nil
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyEpcPolicy FastPath Check Failed!")
	}

	_, policyData = table.lookupAllByKey(key)
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
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[16], groupAny, IPProtocolTCP, 8000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group1Ip3, IPProtocolTCP, 0, 8000)
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyEpcIpGroup Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, group2Ip2, group1Ip3, IPProtocolTCP, 0, 8000)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPolicyEpcIpGroup Check Failed!")
	}
}

func TestDdbsIpGroupPortAcl(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	// group1->group2,tcp,vlan:10,dstport:20
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 20)
	// group2->group1,tcp,vlan:10,dstport:21
	action2 := toNpbAction(12, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 12, group[2], group[1], IPProtocolTCP, 21)
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)
	// 构建查询key  1:21->2:20 tcp vlan:10 ,匹配两条acl
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 21, 20)
	_, policyData := table.lookupAllByKey(key)
	backward := action2.ReverseTapSide()
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action, backward}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestIpGroupPortAcl Check Failed!")
	}
}

func TestDdbsResourceGroupPolicy(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	// acl1: dstGroup:group1
	// group1: epcId=10,mac=group1Mac,ips="group1Ip1/24,group1Ip2/25",subnetId=121
	action1 := toNpbAction(16, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(table, action1, 16, groupAny, group[1], protoAny, -1)
	acls = append(acls, acl1)
	table.UpdateAcls(acls)
	// 构建查询1-key  (group1)group1Ip1:10->(group1)group1Ip2:10 proto:6
	key := generateLookupKey(group1Mac, group1Mac, group1Ip1, group1Ip2, IPProtocolTCP, 10, 10)
	_, policyData := table.lookupAllByKey(key)
	backward := action1.ReverseTapSide()
	// 可匹配acl1，direction=3
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action1, backward}, acl1.Id)
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
	// group5: 1.epcId=-1,mac=group5Mac1,ips="group5Ip1/24,group5Ip2/32"
	//         2.epcId=50,mac=group5Mac2,ips="group5Ip1/24,group5Ip2/32"
	action2 := toNpbAction(18, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 18, groupAny, group[5], protoAny, -1)
	action3 := toNpbAction(19, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl3 := generatePolicyAcl(table, action3, 19, group[3], group[5], IPProtocolUDP, 1023)
	acls = append(acls, acl2, acl3)
	table.UpdateAcls(acls)
	// 2-key  (group5)group5Ip1:1000->(group5)group5Ip2:1023 udp
	key = generateLookupKey(group5Mac1, group5Mac1, group5Ip1, group5Ip2, IPProtocolUDP, 1000, 1023)
	_, policyData = table.lookupAllByKey(key)
	backward = action2.ReverseTapSide()
	// 匹配action2及backward，但不匹配action3
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2, backward}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key Check Failed!")
	}

	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 2-key FastPath Check Failed!")
	}
	// 3-key  非资源组ip5->(group5)group5Ip1  3和4都可匹配action2
	key = generateLookupKey(macAny, group5Mac1, ip5, group5Ip1, IPProtocolUDP, 1000, 1023)
	_, policyData = table.lookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 3-key FastPath Check Failed!")
	}
	// 4-key 非资源组ip1->(group5)group5Ip2
	key = generateLookupKey(macAny, group5Mac1, ip1, group5Ip2, IPProtocolUDP, 1000, 1023)
	_, policyData = table.lookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 4-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 4-key FastPath Check Failed!")
	}
	// 5-key (group3)group3Ip1网段云外ip6:1000 -> (group5)group5Ip1网段云外ip7:1023 udp
	key = generateLookupKey(group3Mac1, group5Mac1, ip6, ip7, IPProtocolUDP, 1000, 1023)
	_, policyData = table.lookupAllByKey(key)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action3, action2}, acl3.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy: 5-key Check Failed!")
	}
	_, policyData = getPolicyByFastPath(table, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("ResourceGroupPolicy 5-key FastPath Check Failed!")
	}
}

func TestDdbsSrcDevGroupDstIpGroupPolicy(t *testing.T) {
	table := generatePolicyTable(DDBS)
	acls := []*Acl{}
	// acl1: dstGroup: ipGroup6(IP资源组)，udp
	// acl2: srcGroup: group3(DEV资源组)，udp
	action1 := toNpbAction(20, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(table, action1, 20, groupAny, group[6], IPProtocolUDP, -1)
	action2 := toNpbAction(21, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 21, group[3], groupAny, IPProtocolUDP, -1)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group3/ipGroup6)group3Ip1 -> (ipGroup6)ipGroup6Ip3 udp
	key1 := generateLookupKey(group3Mac1, ipGroup6Mac1, group3Ip1, ipGroup6Ip3, IPProtocolUDP, 0, 0)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	backward1 := action1.ReverseTapSide()
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.Merge([]NpbActions{action2, action1, backward1}, acl2.Id) // 可以匹配backward1
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group3)group3Ip2 -> (group3/ipGroup6)group3Ip1
	key2 := generateLookupKey(group3Mac1, ipGroup6Mac1, group3Ip2, group3Ip1, IPProtocolUDP, 0, 0)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	backward2 := action2.ReverseTapSide()
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]NpbActions{action1, backward2}, acl1.Id)
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
	action3 := toNpbAction(22, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl3 := generatePolicyAcl(table, action3, 22, groupAny, group[7], IPProtocolUDP, -1)
	action4 := toNpbAction(23, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl4 := generatePolicyAcl(table, action4, 23, group[4], groupAny, IPProtocolUDP, -1)
	acls = append(acls, acl3, acl4)
	table.UpdateAcls(acls)

	// key3: (group3/group6)group3Ip1:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key3 := generateLookupKey(group3Mac1, macAny, group3Ip1, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key3)
	// 匹配ipGroup6、group3，ipGroup7有epc限制，group4mac不符
	policyData = getPolicyByFirstPath(table, result, key3)
	basicPolicyData3 := new(PolicyData)
	basicPolicyData3.Merge([]NpbActions{action2, action1, backward1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key4 := generateLookupKey(group4Mac1, group5Mac1, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key4)
	// 源端匹配group4不匹配group3，目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key4)
	basicPolicyData4 := new(PolicyData)
	basicPolicyData4.Merge([]NpbActions{action4, action1}, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group4)group4Ip2:8000 -> (ipGroup5/ipGroup6/ipGroup7)ipGroup6Ip3:6000 udp
	key5 := generateLookupKey(group4Mac1, macAny, group4Ip2, ipGroup6Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key5)
	// 源端匹配group4不匹配group3,目的端匹配ipGroup6不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key5)
	basicPolicyData5 := new(PolicyData)
	basicPolicyData5.Merge([]NpbActions{action4, action1}, acl4.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
	}

	// key6: (mac、ip不匹配) group3Ip2 :8000 -> (ipGroup6/ipGroup7)ipGroup7Ip3:6000 udp
	key6 := generateLookupKey(group5Mac2, ipGroup7Mac1, group3Ip2, ipGroup7Ip3, IPProtocolUDP, 8000, 6000)
	result = getEndpointData(table, key6)
	// 源端不匹配group3/group4,目的端匹配ipGroup6，不匹配ipGroup7
	policyData = getPolicyByFirstPath(table, result, key6)
	basicPolicyData6 := new(PolicyData)
	basicPolicyData6.Merge([]NpbActions{action1}, acl1.Id)
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
	action1 := toNpbAction(24, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(table, action1, 24, group[5], groupAny, IPProtocolTCP, 8000)
	action2 := toNpbAction(25, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 25, group[5], groupAny, protoAny, portAny)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)

	// key1: (group5)group5Ip1:6000 -> (ipGroup5/ipGroup6)ipGroup6Ip3:8000 tcp vlan:10
	key1 := generateLookupKey(group5Mac1, ipGroup6Mac1, group5Ip1, ipGroup6Ip3, IPProtocolTCP, 6000, 8000)
	result := getEndpointData(table, key1)
	policyData := getPolicyByFirstPath(table, result, key1)
	// 可匹配acl1，direction=3; 可匹配acl2，direction=1
	backward1 := action1.ReverseTapSide()
	backward2 := action2.ReverseTapSide()
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.NpbActions = make([]NpbActions, 0, 2)
	basicPolicyData1.Merge([]NpbActions{action2, action1, backward2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData) {
		t.Error("key1 FirstPath Check Failed! ", result)
	}

	// key2:(ipGroup6)ipGroup6Ip2:6000 -> (group5)group5Ip1:8000 tcp vlan:10
	key2 := generateLookupKey(ipGroup6Mac1, group5Mac1, ipGroup6Ip2, group5Ip1, IPProtocolTCP, 6000, 8000)
	result = getEndpointData(table, key2)
	policyData = getPolicyByFirstPath(table, result, key2)
	// 不能匹配acl1
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]NpbActions{backward2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group5)group5Ip2:8000 -> (group5)group5Ip1:8000 tcp
	key3 := generateLookupKey(group5Mac2, group5Mac1, group5Ip2, group5Ip1, IPProtocolTCP, 8000, 8000)
	result = getEndpointData(table, key3)
	policyData = getPolicyByFirstPath(table, result, key3)
	// 可匹配acl1，direction=3；可匹配acl2，direction=3
	basicPolicyData3 := new(PolicyData)
	basicPolicyData3.NpbActions = make([]NpbActions, 0, 4)
	basicPolicyData3.Merge([]NpbActions{action2, action1, backward1, backward2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData3, policyData) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group5)group5Ip1:6000 -> (ipGroup6)ipGroup6Ip2:8000 udp
	key4 := generateLookupKey(group5Mac1, ipGroup6Mac1, group5Ip1, ipGroup6Ip2, IPProtocolUDP, 6000, 8000)
	result = getEndpointData(table, key4)
	policyData = getPolicyByFirstPath(table, result, key4)
	// udp协议，不匹配acl1
	basicPolicyData4 := new(PolicyData)
	basicPolicyData4.Merge([]NpbActions{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData4, policyData) {
		t.Error("key4 FirstPath Check Failed!")
	}

	// key5: (group5)group5Ip1:6000 -> (ipGroup6)ipGroup6Ip2:6000
	key5 := generateLookupKey(group5Mac1, ipGroup6Mac1, group5Ip1, ipGroup6Ip2, IPProtocolTCP, 6000, 6000)
	result = getEndpointData(table, key5)
	policyData = getPolicyByFirstPath(table, result, key5)
	// port不一致，不匹配acl1
	basicPolicyData5 := new(PolicyData)
	basicPolicyData5.Merge([]NpbActions{action2}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key5 FirstPath Check Failed!")
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
		t.Error("key5 FastPath Check Failed!")
	}

	// key5 - fastpath
	_, policyData = getPolicyByFastPath(table, key5)
	if !CheckPolicyResult(t, basicPolicyData5, policyData) {
		t.Error("key6 FastPath Check Failed!")
	}
}

func TestDdbsEndpointDataDirection(t *testing.T) {
	table := generatePolicyTable(DDBS)
	acls := []*Acl{}
	// acl1: dstGroup:group4, dstPort:1000 tcp
	// acl2: srcGroup:group3, dstPort:1000 tcp
	action1 := toNpbAction(25, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(table, action1, 25, groupAny, group[4], IPProtocolTCP, 1000)
	action2 := toNpbAction(26, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(table, action2, 26, group[3], groupAny, IPProtocolTCP, 1000)
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)
	// key1: (group3/ipGroup6)group3Ip1:1023 -> (group4)group4Ip2:1000 tcp
	key1 := generateLookupKey(group3Mac1, group4Mac1, group3Ip1, group4Ip2, IPProtocolTCP, 1023, 1000)
	key1.L3End1 = true
	// src: DEV-30, IP-60 dst: DEV-40
	result := getEndpointData(table, key1)
	basicData1 := new(EndpointData)
	basicData1.SrcInfo = generateEndpointInfo(groupEpc[3], groupEpc[4], l2EndBool[0], l3EndBool[0], true)
	basicData1.DstInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], true)
	if !CheckEndpointDataResult(t, basicData1, result) {
		t.Error("key1 EndpointData Check Failed!")
	}

	policyData1 := getPolicyByFirstPath(table, result, key1)
	basicPolicyData1 := new(PolicyData)
	basicPolicyData1.Merge([]NpbActions{action2, action1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData1, policyData1) {
		t.Error("key1 FirstPath Check Failed!")
	}

	// key2: (group4)group4Ip2:1000 -> (group3/ipGroup6)group3Ip1:1023 tcp
	key2 := generateLookupKey(group4Mac1, group3Mac1, group4Ip2, group3Ip1, IPProtocolTCP, 1000, 1023)
	key2.L3End0 = true
	// src: DEV-40 dst: DEV-30, IP-60
	result = getEndpointData(table, key2)
	basicData2 := new(EndpointData)
	basicData2.SrcInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], true)
	basicData2.DstInfo = generateEndpointInfo(groupEpc[3], groupEpc[4], l2EndBool[0], l3EndBool[0], true)
	if !CheckEndpointDataResult(t, basicData2, result) {
		t.Error("key2 EndpointData Check Failed!")
	}
	policyData2 := getPolicyByFirstPath(table, result, key2)
	backward1 := action1.ReverseTapSide()
	backward2 := action2.ReverseTapSide()
	basicPolicyData2 := new(PolicyData)
	basicPolicyData2.Merge([]NpbActions{backward2, backward1}, acl2.Id)
	if !CheckPolicyResult(t, basicPolicyData2, policyData2) {
		t.Error("key2 FirstPath Check Failed!")
	}

	// key3: (group3/ipGroup6)group3Ip1:1000 -> (group4)group4Ip2:1023 tcp
	key3 := generateLookupKey(group3Mac1, group4Mac1, group3Ip1, group4Ip2, IPProtocolTCP, 1000, 1023)
	key3.L3End1 = true
	// src: DEV-30, IP-60 dst: DEV-40
	result = getEndpointData(table, key3)
	basicData3 := new(EndpointData)
	basicData3.SrcInfo = generateEndpointInfo(groupEpc[3], groupEpc[4], l2EndBool[0], l3EndBool[0], true)
	basicData3.DstInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], true)
	if !CheckEndpointDataResult(t, basicData3, result) {
		t.Error("key3 EndpointData Check Failed!")
	}
	policyData3 := getPolicyByFirstPath(table, result, key3)
	basicPolicyData3 := INVALID_POLICY_DATA
	if !CheckPolicyResult(t, basicPolicyData3, policyData3) {
		t.Error("key3 FirstPath Check Failed!")
	}

	// key4: (group4)group4Ip2:1023 -> (group3/ipGroup6)group3Ip1:1000 tcp
	key4 := generateLookupKey(group4Mac1, group3Mac1, group4Ip2, group3Ip1, 6, 1023, 1000)
	key4.L3End0 = true
	// src: DEV-40 dst: DEV-30, IP-60
	result = getEndpointData(table, key4)
	basicData4 := new(EndpointData)
	basicData4.SrcInfo = generateEndpointInfo(groupEpc[4], groupEpc[4], l2EndBool[0], l3EndBool[1], true)
	basicData4.DstInfo = generateEndpointInfo(groupEpc[3], groupEpc[4], l2EndBool[0], l3EndBool[0], true)
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

	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb1 := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 100)
	npb2 := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 200)
	npb3 := toNpbAction(20, 200, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 200)
	npb := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 200)

	acl1 := generatePolicyAcl(table, npb1, 25, groupAny, groupAny, IPProtocolTCP, 1000)
	// acl2 Group: 0 -> 0 Port: 1000 Proto: 0 vlan: any
	acl2 := generatePolicyAcl(table, npb2, 26, groupAny, groupAny, protoAny, 1000)
	// acl3 Group: 0 -> 0 Port: 0 Proto: 6 vlan: any
	acl3 := generatePolicyAcl(table, npb3, 27, groupAny, groupAny, IPProtocolUDP, 1000)
	acls = append(acls, acl1, acl2, acl3)
	table.UpdateAcls(acls)
	// 构建预期结果
	basicPolicyData := &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb.ReverseTapSide()}, 26, BACKWARD)

	// key1: ip4:1000 -> ip3:1023 tcp
	key1 := generateLookupKey(mac2, mac1, group2Ip1, group1Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, false, true)
	key1.L3End1 = true
	_, policyData := table.lookupAllByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key1: ip3:1023 -> ip4:1000 tcp
	key1 = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key1)
	basicPolicyData = &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb1, npb2}, 26)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}

	// key2: ip3:1023 -> ip4:1000 udp
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb3, npb2}, 27)
	key2 := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolUDP, 1023, 1000, NPB)
	setEthTypeAndOthers(key2, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key2)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbAction Check Failed!")
	}
}

func TestDdbsMultiNpbAction1(t *testing.T) {
	table := generatePolicyTable(DDBS)
	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 100)
	// VMA -> ANY SRC
	acl := generatePolicyAcl(table, npb, 25, group[1], groupAny, IPProtocolTCP, portAny)
	// VMB -> ANY SRC
	acl2 := generatePolicyAcl(table, npb, 25, group[2], groupAny, IPProtocolTCP, portAny)
	// VMA -> VMB SRC
	acl3 := generatePolicyAcl(table, npb, 25, group[1], group[2], IPProtocolTCP, portAny)
	// VMB -> VMA SRC
	acl4 := generatePolicyAcl(table, npb, 25, group[2], group[1], IPProtocolTCP, portAny)
	acls := []*Acl{acl, acl2, acl3, acl4}
	table.UpdateAcls(acls)
	basicPolicyData := &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{}, 0)

	// key: false:ip1:1000 -> true:ip2:1023 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData := table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
		t.Error(cap(basicPolicyData.NpbActions))
		t.Error(cap(policyData.NpbActions))
	}

	// key: true:ip2:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1023 -> ture:ip1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip2:1023 tcp
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip1:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, group1Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip1:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group1Mac, mac3, group1Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, ip3, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip1:1000 tcp
	key = generateLookupKey(mac3, group1Mac, ip3, group1Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	key.L3End1 = true
	_, policyData = table.lookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip2:1000 -> false:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, group2Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip2:1000 -> true:ip3:1023 tcp
	key = generateLookupKey(group2Mac, mac3, group2Ip1, ip3, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: true:ip3:1023 -> false:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, ip3, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, false)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}

	// key: false:ip3:1023 -> true:ip2:1000 tcp
	key = generateLookupKey(mac3, group2Mac, ip3, group2Ip1, IPProtocolTCP, 1023, 1000, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, false, true)
	key.L3End1 = true
	_, policyData = table.lookupAllByKey(key)
	*basicPolicyData = PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb.ReverseTapSide()}, 25)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestMultiNpbAction Check Failed!")
	}
}

func TestDdbsNpbActionDedup(t *testing.T) {
	table := generatePolicyTable(DDBS)
	npb1 := toNpbAction(10, 100, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 100)
	npb2 := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 0)
	// VM段-A -> ANY, DEV-group2 -> ANY
	acl1 := generatePolicyAcl(table, npb1, 25, group[2], groupAny, IPProtocolTCP, portAny)
	// IP段-A -> ANY, IP-group3 -> ANY
	acl2 := generatePolicyAcl(table, npb2, 26, group[6], groupAny, IPProtocolTCP, portAny)
	acls := []*Acl{acl1, acl2}
	table.UpdateAcls(acls)

	basicPolicyData := new(PolicyData)
	basicPolicyData.MergeNpbAction([]NpbActions{npb1, npb2.ReverseTapSide()}, 25)
	// key: true:group3Ip1:1000 -> true:ipGroup6Ip2:1023 tcp
	key := generateLookupKey(group2Mac, group4Mac1, group3Ip3, ipGroup6Ip2, IPProtocolTCP, 1000, 1023, NPB)
	key.L3End1 = true
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint := modifyEndpointDataL3End(table, key, l3EndBool[1], l3EndBool[1])
	policyData := getPolicyByFirstPath(table, endpoint, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionDedup Check Failed!")
	}

	// IP段-A -> IP段-B, IP-group3 -> IP-group6
	npb5 := toNpbAction(20, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 100)
	acl5 := generatePolicyAcl(table, npb5, 29, group[6], group[6], IPProtocolTCP, -1)
	acls = []*Acl{acl5}
	table.UpdateAcls(acls)

	basicPolicyData = new(PolicyData)
	basicPolicyData.MergeNpbAction([]NpbActions{npb5, npb5.ReverseTapSide()}, acl5.Id)
	basicPolicyData.FormatNpbAction()
	// key: true:(IP-group6)ipGroup6Ip2:1000 -> true:(IP-group6)ipGroup6Ip4:1023 tcp
	key = generateLookupKey(ipGroup6Mac1, ipGroup6Mac1, ipGroup6Ip2, ipGroup6Ip4, IPProtocolTCP, 1000, 1023, NPB)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	endpoint = modifyEndpointDataL3End(table, key, l3EndBool[1], l3EndBool[1])
	policyData = getPolicyByFirstPath(table, endpoint, key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionDedup Check Failed!")
	}
}

func TestDdbsPcapNpbAction(t *testing.T) {
	table := generatePolicyTable(DDBS)
	acls := []*Acl{}

	// acl1 Group: 16 -> 16 Port: 0 Proto: TCP vlan: any Tap: any
	npb := toPcapAction(10, 150, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(table, npb, 25, group[16], group[16], IPProtocolTCP, -1)
	acl1.TapType = 0
	acls = append(acls, acl1)
	table.UpdateAcls(acls)
	// 构建预期结果
	basicPolicyData := &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb, npb.ReverseTapSide()}, 25)

	// key1: ip4:1000 -> ip3:1023 tcp
	key1 := generateLookupKey(group1Mac, group1Mac, group1Ip1, group1Ip2, IPProtocolTCP, 1000, 1023, NPB)
	key1.TapType = TAP_IDC_MIN
	_, policyData := table.lookupAllByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPcapNpbAction Check Failed!")
	}
}

func TestDdbsNpbActionAclGids(t *testing.T) {
	table := generatePolicyTable(DDBS)
	acls := []*Acl{}

	// acl1 Group: 0 -> 0 Port: 0 Proto: 17 vlan: any
	npb1 := toNpbAction(10, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 100)
	acl1 := generatePolicyAcl(table, npb1, 25, groupAny, groupAny, IPProtocolTCP, 1000)
	acl1.TapType = 223
	// acl2 Group: 0 -> 0 Port: 1000 Proto: 0 vlan: any
	npb2 := toNpbAction(11, 150, NPB_TUNNEL_TYPE_VXLAN, TAPSIDE_SRC, 200)
	acl2 := generatePolicyAcl(table, npb2, 26, groupAny, groupAny, protoAny, 1000)
	acl2.TapType = 223
	acls = append(acls, acl1, acl2)
	table.UpdateAcls(acls)
	// 构建预期结果
	basicPolicyData := &PolicyData{}
	basicPolicyData.MergeNpbAction([]NpbActions{npb2, npb1.ReverseTapSide()}, 26, BACKWARD)

	// key1: ip4:1000 -> ip3:1023 tcp
	key1 := generateLookupKey(mac2, mac1, group2Ip1, group1Ip1, IPProtocolTCP, 1000, 1023, NPB)
	key1.TapType = 223
	setEthTypeAndOthers(key1, EthernetTypeIPv4, 64, false, true)
	_, policyData := table.lookupAllByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionAclGids Check Failed!")
	}

	_, policyData = table.lookupAllByKey(key1)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestNpbActionAclGids Fast Check Failed!")
	}
}

func TestDdbsPolicyDoublePort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:8000 tcp
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	acl.SrcPortRange = append(acl.SrcPortRange[:0], NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询2-key  2:8000->1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key)
	backward := action.ReverseTapSide()
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicyDoubulePort Check Failed!")
	}
}

func TestDdbsPolicySrcPort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1:1000->2:ANY tcp
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, portAny)
	acl.SrcPortRange = append(acl.SrcPortRange[:0], NewPortRange(1000, 1000))
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:1000->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询2-key  2:8000->1:1000 tcp
	key = generateLookupKey(group2Mac, group1Mac, group2Ip1, group1Ip1, IPProtocolTCP, 8000, 1000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key)
	backward := action.ReverseTapSide()
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询3-key  1:2000->2:8000 tcp
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 2000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}

	// 构建查询4-key  1:1000->2:7000 tcp
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 1000, 7000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, true, true)
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestPolicySrcPort Check Failed!")
	}
}

func TestDdbsTapType(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000 tapType=0|1
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	action2 := toNpbAction(100, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	acl.TapType = 1
	acl2 := generatePolicyAcl(table, action2, 100, group[1], group[2], IPProtocolTCP, 8000)
	acl2.TapType = 0
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp tapType=1
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	key.TapType = GetTapType(0x10001)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2, action}, acl2.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsTapType Check Failed!")
	}

	// 构建查询1-key  1:0->2:8000 tcp tapType=2
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	key.TapType = GetTapType(0x10002)

	// 获取查询first结果
	_, policyData = table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action2}, acl2.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsTapType Check Failed!")
	}
}

func TestDdbsInternet(t *testing.T) {
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acls := []*Acl{}
	acl := generatePolicyAcl(table, action, 10, group[1], uint32(GROUP_INTERNET&0xffff), IPProtocolTCP, 8000)
	acls = append(acls, acl)
	ipGroups := make([]*IpGroupData, 0, 1)
	ipGroup1 := generateIpGroup(group[1], groupEpc[1], group1Ip1Net)
	ipGroups = append(ipGroups, ipGroup1, generateIpGroup(GROUP_INTERNET&0xffff, EPC_FROM_INTERNET, "0.0.0.0/0")) // internet
	table.UpdateIpGroupData(ipGroups)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp, 这里dstMac使用一个不在Platform中的，避免获取到资源组
	key := generateLookupKey(group1Mac, 100, group1Ip1, queryIp, IPProtocolTCP, 0, 8000)
	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsInternet Check Failed!")
	}
}

func TestDdbsPolicyIpv6(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	action2 := toNpbAction(20, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	// ip: 0.0.0.0/32 epc: 0, IP为0的流量, 对于非IP流量会用0来查询策略
	acl2 := generatePolicyAcl(table, action2, 20, group[17], groupAny, protoAny, 0)
	acls = append(acls, acl, acl2)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp, 会匹配acl,不会匹配acl2
	key := generateLookupKey6(group1Mac, group2Mac, ip12, ip13, IPProtocolTCP, 0, 8000)
	key.L3End0, key.L3End1 = true, true

	// 获取查询first结果
	endpoints, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) || endpoints.SrcInfo.L3End != true || endpoints.DstInfo.L3End != true {
		t.Error(endpoints)
		t.Error("TestDdbsPolicyIpv6 Check Failed!")
	}
}

func TestDdbsPolicyIpv6WithIpGroup(t *testing.T) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	// ip6 -> ip6
	acl := generatePolicyAcl(table, action, 10, group[10], group[11], IPProtocolTCP, 8000)
	// ip6 -> dev
	acl2 := generatePolicyAcl(table, action, 20, group[10], group[1], IPProtocolTCP, 8000)
	// dev -> dev
	acl3 := generatePolicyAcl(table, action, 30, group[1], group[2], IPProtocolTCP, 8000)
	acls = append(acls, acl, acl2, acl3)
	table.UpdateAcls(acls)
	// 构建查询1-key  8:0->9:8000 tcp ip6 -> ip6
	key := generateLookupKey6(group3Mac1, group4Mac1, ipGroup10Ip1, ipGroup11Ip1, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyIpv6WithIpGroup Check Failed!")
	}

	// 构建查询1-key  8:0->9:8000 tcp ip6 -> dev
	key = generateLookupKey6(group5Mac1, group1Mac, ipGroup10Ip1, ip12, IPProtocolTCP, 0, 8000)

	_, policyData = table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl2.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyIpv6WithIpGroup Check Failed!")
	}

	// 构建查询1-key  8:0->9:8000 tcp dev -> dev
	key = generateLookupKey6(group1Mac, group2Mac, ip12, ip13, IPProtocolTCP, 0, 8000)

	_, policyData = table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData = new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl3.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPolicyIpv6WithIpGroup Check Failed!")
	}
}

func TestDdbsPeerConnection(t *testing.T) {
	table := generatePolicyTable(DDBS)
	// group2Ip1对应EPC有两个分别为12和20，若没有对等连接查询，会查询到12
	key := generateLookupKey(group1Mac, mac3, group1Ip1, group2Ip1, IPProtocolUDP, 0, 0)
	endpoints, _ := table.lookupAllByKey(key)
	if endpoints.DstInfo.L3EpcId != 20 {
		t.Error(endpoints)
		t.Error("TestDdbsPeerConnection Check Failed!")
	}
}

func TestDdbsPort(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 1000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 1000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)

	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 1000)

	// 获取查询first结果
	_, policyData = table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	// 获取查询fast结果
	_, policyData = table.lookupAllByKey(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	// 全采集
	acl = generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, -1)
	acls = append(acls[:0], acl)
	table.UpdateAcls(acls)
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	// 采集端口0
	acl = generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0)
	acl.SrcPortRange = []PortRange{NewPortRange(200, 200)}
	acls = append(acls[:0], acl)
	table.UpdateAcls(acls)
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 200, 0)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	// fast
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 200, 0)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 200, 8000)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}
}

func TestDdbsProtocol(t *testing.T) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], 0, 0)
	acls = append(acls, acl)
	table.UpdateAcls(acls)

	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 0)
	// 获取查询first结果
	_, policyData := table.lookupAllByKey(key)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, INVALID_POLICY_DATA, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, 0, 0, 0)
	// 获取查询first结果
	_, policyData = table.lookupAllByKey(key)
	// 构建预期结果
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action}, acl.Id)
	// 查询结果和预期结果比较
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}

	// 全采集
	acl = generatePolicyAcl(table, action, 10, group[1], group[2], PROTO_ALL, 0)
	acls = append(acls[0:], acl)
	table.UpdateAcls(acls)
	key = generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 0)
	_, policyData = table.lookupAllByKey(key)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDdbsPort0 Check Failed!")
	}
}

func TestDdbsCidr(t *testing.T) {
	// 创建 policyTable
	table := NewPolicyTable(1, 2, 1024, false, DDBS)
	cidr := generateCidr(10, 1, "192.168.2.12/24")
	table.UpdateCidrs([]*Cidr{cidr})

	// 192.168.2.12 > 192.168.10.10
	key := generateLookupKey(0, 0, ip1, ip7, IPProtocolTCP, 0, 0)
	endpointData, _ := table.lookupAllByKey(key)
	if endpointData.SrcInfo.L3EpcId != 10 {
		t.Error(endpointData)
	}

	// 192.168.0.12 > 192.168.10.10
	key1 := generateLookupKey(0, 0, ip4, ip7, IPProtocolTCP, 0, 0)
	endpointData, _ = table.lookupAllByKey(key1)
	if endpointData.SrcInfo.L3EpcId == 10 {
		t.Error(endpointData)
	}
}

func TestDdbsMemory(t *testing.T) {
	table := generatePolicyTable(DDBS)
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[18], group[19], IPProtocolTCP, 0)
	acl.DstPortRange = []PortRange{
		NewPortRange(9012, 9012),
		NewPortRange(7007, 7007),
		NewPortRange(7004, 7004),
		NewPortRange(9003, 9003),
		NewPortRange(7016, 7016),
		NewPortRange(9208, 9208),
		NewPortRange(7018, 7018),
		NewPortRange(7777, 7777),
		NewPortRange(8004, 8004),
		NewPortRange(8002, 8002),
		NewPortRange(8001, 8001),
		NewPortRange(8009, 8009),
		NewPortRange(8010, 8010),
		NewPortRange(8003, 8003),
		NewPortRange(80, 80),
		NewPortRange(8000, 8000),
		NewPortRange(9500, 9500),
		NewPortRange(8800, 8800),
		NewPortRange(9002, 9002),
		NewPortRange(8100, 8100),
		NewPortRange(8600, 8600),
		NewPortRange(9000, 9000),
		NewPortRange(8700, 8700),
		NewPortRange(9900, 9900),
		NewPortRange(6902, 6902),
		NewPortRange(6904, 6904),
		NewPortRange(6912, 6912),
		NewPortRange(6914, 6914),
		NewPortRange(6922, 6922),
		NewPortRange(6924, 6924),
		NewPortRange(6932, 6932),
		NewPortRange(6942, 6942),
		NewPortRange(6952, 6952),
		NewPortRange(6954, 6954),
		NewPortRange(6962, 6962),
		NewPortRange(6972, 6972),
		NewPortRange(6982, 6982),
		NewPortRange(6992, 6992),
		NewPortRange(30000, 30000),
		NewPortRange(7402, 7402),
		NewPortRange(8300, 8300),
		NewPortRange(8500, 8500),
		NewPortRange(9300, 9300),
		NewPortRange(7001, 7001),
		NewPortRange(8180, 8180),
		NewPortRange(8514, 8514),
		NewPortRange(9001, 9001),
		NewPortRange(8011, 8011),
		NewPortRange(6800, 6800),
		NewPortRange(9200, 9200),
		NewPortRange(9100, 9100),
		NewPortRange(7510, 7510),
		NewPortRange(31800, 31800),
		NewPortRange(8210, 8210),
		NewPortRange(1401, 1401),
		NewPortRange(5555, 5555),
		NewPortRange(1500, 1500),
		NewPortRange(7070, 7070),
		NewPortRange(8105, 8105),
		NewPortRange(4101, 4101),
		NewPortRange(8060, 8060),
		NewPortRange(8090, 8090),
		NewPortRange(8014, 8014),
		NewPortRange(9132, 9132),
		NewPortRange(1601, 1601),
		NewPortRange(8201, 8201),
		NewPortRange(7006, 7006),
		NewPortRange(7707, 7707),
		NewPortRange(7110, 7110),
		NewPortRange(4201, 4201),
		NewPortRange(8900, 8900),
		NewPortRange(8015, 8015),
		NewPortRange(6060, 6060),
		NewPortRange(10009, 10009),
		NewPortRange(8099, 8099),
		NewPortRange(7005, 7005),
		NewPortRange(9011, 9011),
		NewPortRange(7501, 7501),
		NewPortRange(11007, 11007),
		NewPortRange(10003, 10003),
		NewPortRange(7002, 7002),
		NewPortRange(6800, 6800),
		NewPortRange(7008, 7008),
	}
	acls := []*Acl{}
	acls = append(acls, acl)
	// 255万条策略使用225196928字节大约214M常驻内存，策略更新会有些临时内存的申请这里限制到270M内存
	table.UpdateMemoryLimit(270 << 20)
	err := table.UpdateAcls(acls)
	if err != nil {
		t.Errorf("TestDdbsMemory error: %v", err)
	}
}

func BenchmarkDdbsAcl(b *testing.B) {
	acls := []*Acl{}
	table := generatePolicyTable(DDBS)
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)

	for i := uint16(1); i <= 1000; i++ {
		acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 0)

		acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(1+10*i, 100+10*i))
		acl.DstPortRange = append(acl.DstPortRange, NewPortRange(30000+10*i, 30100+10*i))
		acl.SrcGroups = acl.SrcGroups[:0]
		acl.DstGroups = acl.DstGroups[:0]
		for j := 100; j < 200; j++ {
			acl.SrcGroups = append(acl.SrcGroups, uint32(j))
			acl.DstGroups = append(acl.DstGroups, uint32(j))
		}

		acls = append(acls, acl)
	}
	b.ResetTimer()
	table.UpdateAcls(acls)
}

func BenchmarkDdbsFastPath(b *testing.B) {
	acls := []*Acl{}
	// 创建 policyTable
	table := generatePolicyTable(DDBS)
	// 构建acl action  1->2 tcp 8000
	action := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl := generatePolicyAcl(table, action, 10, group[1], group[2], IPProtocolTCP, 8000)
	acls = append(acls, acl)
	table.UpdateAcls(acls)
	// 构建查询1-key  1:0->2:8000 tcp
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	policy := new(PolicyData)
	endpoint := getEndpointData(table, key)
	getPolicyByFirstPath(table, endpoint, key)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		table.operator.GetPolicyByFastPath(key, policy)
	}
}
