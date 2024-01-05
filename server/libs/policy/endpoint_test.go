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
	"time"

	. "github.com/google/gopacket/layers"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

// 平台信息有关测试
func TestGetPlatformData(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	datas := make([]PlatformData, 0, 2)
	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// epcId:40 DeviceType:2 DeviceId:3 IfType:3 Mac:mac4
	vifData := generatePlatformDataExtension(groupEpc[4], 3, mac4)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	ipInfo2 := generateIpNet(ip2, 125, 24)
	ipInfo3 := generateIpNet(ip1, 126, 32)
	vifData1 := generatePlatformDataExtension(groupEpcAny, 3, mac2)
	vifData1.Ips = append(vifData1.Ips, ipInfo2, ipInfo3)

	datas = append(datas, vifData, vifData1)
	policy.UpdateInterfaceData(datas)

	key := generateLookupKey(mac4, mac2, ip2, ip4, 0, 0, 0)
	result, _ := policy.lookupAllByKey(key)
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
}

func TestGetPlatformDataAboutArp(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	datas := make([]PlatformData, 0, 2)

	ipInfo := generateIpNet(ip3, 121, 24)
	ipInfo1 := generateIpNet(ip4, 122, 25)
	// epcId:40 DeviceType:2 DeviceId:3 IfType:3 Mac:mac4
	vifData := generatePlatformDataExtension(groupEpc[4], 3, mac4)
	vifData.Ips = append(vifData.Ips, ipInfo, ipInfo1)

	datas = append(datas, vifData)
	policy.UpdateInterfaceData(datas)

	key := generateClassicLookupKey(mac4, mac3, ip4, ip3, 0, 0, EthernetTypeARP)
	now := time.Now()
	result, _ := policy.lookupAllByKey(key)
	t.Log(time.Now().Sub(now))
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	now = time.Now()
	result, _ = policy.lookupAllByKey(key)
	t.Log(time.Now().Sub(now))
}

func TestGetGroupData(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	policy.UpdateAcls(nil)

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	now := time.Now()
	result, _ := policy.lookupAllByKey(key)
	t.Log(time.Now().Sub(now))
	if result != nil {
		t.Log(result.SrcInfo, "\n")
		t.Log(result.DstInfo, "\n")
	}
	now = time.Now()
	result, _ = policy.lookupAllByKey(key)
	t.Log(time.Now().Sub(now))
}

// 测试全局Pass策略匹配direction==3
func TestAllPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, portAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAllPassPolicy Check failed!")
	}
}

// 测试资源组forward策略匹配 direction==1
func TestGroupForwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// srcGroups: 40
	acl1 := generatePolicyAcl(policy, forward, 10, group[4], groupAny, protoAny, portAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{forward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestGroupForwardPassPolicy Check Failed!")
	}
}

// 测试资源组backward策略匹配 direction==2
func TestGroupBackwardPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstGroups: 40
	acl1 := generatePolicyAcl(policy, backward, 10, groupAny, group[4], protoAny, portAny)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 0, 0, EthernetTypeARP)
	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestGroupBackwardPassPolicy Check Failed!")
	}
}

// 测试Port策略匹配 acl配置port=0，查询SrcPort=30，DstPort=30，查询到ACl
func TestAllPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateClassicLookupKey(mac4, mac2, ip4, ip2, 30, 30, EthernetTypeARP)
	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAllPortPassPolicy Check Failed!")
	}
}

// 测试Port策略匹配 acl配置port=30，查询Srcport=30，查到acl的direction=2
func TestSrcPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	// dstPorts : 30
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, ip4, ip2, IPProtocolTCP, 30, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestSrcPortPassPolicy Check Failed!")
	}
}

// 测试Port策略匹配 acl配置port=30，查询Dstport=30，查到acl的direction=1
func TestDstPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, ip4, ip2, IPProtocolTCP, 0, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{forward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestDstPortPassPolicy Check Failed!")
	}
}

// 测试Port策略匹配 acl配置port=30，查询SrcPort=30, Dstport=30，查到acl的direction=3
func TestSrcDstPortPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 30
	acl1 := generatePolicyAcl(policy, forward, 10, groupAny, groupAny, protoAny, 30)
	policy.UpdateAcls([]*Acl{acl1})

	key := generateLookupKey(mac4, mac2, ip4, ip2, IPProtocolTCP, 30, 30)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.lookupAllByKey(key)
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{forward, backward}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestSrcDstPortPassPolicy Check Failed!")
	}
}

// 测试两条acl proto为6和17 查询proto=6的acl,proto为6的匹配成功
func TestAclsPassPolicy(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	generatePlatformData(policy)
	generateIpgroupData(policy)
	//	dstPorts: 8000
	action1 := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl1 := generatePolicyAcl(policy, action1, 10, groupAny, groupAny, IPProtocolTCP, 8000)
	action2 := toNpbAction(20, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	acl2 := generatePolicyAcl(policy, action2, 20, groupAny, groupAny, IPProtocolUDP, 8000)
	policy.UpdateAcls([]*Acl{acl1, acl2})

	key := generateLookupKey(mac4, mac2, ip4, ip2, IPProtocolTCP, 8000, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[0])

	_, policyData := policy.lookupAllByKey(key)

	backward1 := action1.ReverseTapSide()
	basicPolicyData := new(PolicyData)
	basicPolicyData.Merge([]NpbActions{action1, backward1}, acl1.Id)
	if !CheckPolicyResult(t, basicPolicyData, policyData) {
		t.Error("TestAclsPassPolicy Check Failed!")
	}
}

// l2EpcId0=40,L3EpcId0=40,l2Epcid1=-2,L3EpcId1=-2的数据正确性
func TestModifyEpcIdPolicy1(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	policy.UpdateInterfaceData([]PlatformData{platformData1})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac4, mac2, ip4, ip2, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpc[4], groupEpc[4], EPC_FROM_INTERNET, EPC_FROM_INTERNET)
	data, _ := policy.lookupAllByKey(key)
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
	policy := NewPolicyTable(1, 2, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpc[5], 3)
	policy.UpdateInterfaceData([]PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac4, mac5, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(groupEpc[4], groupEpc[4], groupEpc[5], groupEpc[5])
	data, _ := policy.lookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy2 FastPath Check Failed!")
	}
}

// l2EpcId0=-1,l3EpcId0=-1,l2Epcid1=-2,l3EpcId1=50的数据正确性
func TestModifyEpcIdPolicy3(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, EPC_FROM_DEEPFLOW, 3)
	platformData2 := generatePlatformDataByParam(ip5, mac5, groupEpc[5], 3)
	policy.UpdateInterfaceData([]PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	key := generateLookupKey(mac2, mac1, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])

	basicData := generateEpcInfo(EPC_FROM_DEEPFLOW, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET, groupEpc[5])
	data, _ := policy.lookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy3 FastPath Check Failed!")
	}
}

// l3EpcId0=-2, l3EpcId1=-2的数据正确性
func TestModifyEpcIdPolicy5(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	platformData1 := generatePlatformDataByParam(ip4, mac4, EPC_FROM_DEEPFLOW, 4)
	platformData2 := generatePlatformDataByParam(ip5, mac5, EPC_FROM_DEEPFLOW, 4)
	policy.UpdateInterfaceData([]PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)

	// l3EpcId0=-2, l3EpcId1=-2, l2EpcId0=-2, l2EpcId1=-2

	key := generateLookupKey(mac2, mac3, ip4, ip5, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[0], l2EndBool[1])

	basicData := generateEpcInfo(EPC_FROM_INTERNET, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET, EPC_FROM_DEEPFLOW)
	data, _ := policy.lookupAllByKey(key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 Check Failed!")
	}

	data, _ = getPolicyByFastPath(policy, key)
	if !CheckEpcTestResult(t, basicData, data) {
		t.Error("TestModifyEpcIdPolicy5 FastPath Check Failed!")
	}

	// l3EpcId0=-2, l3EpcId1=-2, l2EpcId0=-2, l2EpcId1=-2
	key.SrcMac = mac4
	key.DstMac = mac5
	key.L2End0 = true
	key.L3End1 = true

	basicData = generateEpcInfo(EPC_FROM_DEEPFLOW, EPC_FROM_DEEPFLOW, EPC_FROM_DEEPFLOW, EPC_FROM_DEEPFLOW)
	data, _ = policy.lookupAllByKey(key)
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
	policy := NewPolicyTable(1, 2, 1024, false)
	key := generateLookupKey(mac3, mac4, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[0], l2EndBool[0])

	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[0], l2EndBool[0], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end1 Check Failed!")
	}
}

// L2end0=L2end1=true L3end0=L3end1=false
func TestL2endL3end2(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	key := generateLookupKey(mac3, mac4, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[1])

	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[0], l2EndBool[1], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end2 Check Failed!")
	}
}

// L2end0=L2end1=false L3end0=true,L3end1=false
func TestL2endL3end3(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	key := generateLookupKey(mac3, mac4, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[0], l2EndBool[0])

	basicEndInfo := generateEndInfo(l2EndBool[0], l3EndBool[1], l2EndBool[0], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end3 Check Failed!")
	}
}

// L2end0=L2end1=true L3end0=true, L3end1=false
func TestL2endL3end4(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	key := generateLookupKey(mac3, mac4, ip3, ip4, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 64, l2EndBool[1], l2EndBool[1])

	basicEndInfo := generateEndInfo(l2EndBool[1], l3EndBool[1], l2EndBool[1], l3EndBool[0])
	data := getEndpointData(policy, key)
	if !checkEndTestResult(t, basicEndInfo, data) {
		t.Error("TestL2endL3end4 Check Failed!")
	}
}

// L2end0,L2end1 修正
func TestModifyL2end(t *testing.T) {
	policy := NewPolicyTable(1, 2, 1024, false)
	key := generateLookupKey(mac3, mac4, ip3, ip4, IPProtocolTCP, 0, 8000)
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
	table := NewPolicyTable(1, 2, 1024, false)
	// l2End0=true, l3End0=false, l2End1=false, l3End1=false
	key := generateLookupKey(mac3, mac4, ip3, ip4, 0, 0, 0)
	setEthTypeAndOthers(key, EthernetTypeIPv4, 63, l2EndBool[1], l2EndBool[0])
	policy := new(PolicyData)

	table.lookupAllByKey(key)
	store := table.operator.GetPolicyByFastPath(key, policy)
	if !checkEndpointStore(t, store) {
		t.Error("TestFastpathEndpointStore Check Failed!")
	}
}

func BenchmarkGetEndpointData(b *testing.B) {
	policy := NewPolicyTable(1, 2, 1024, false)
	platformData1 := generatePlatformDataByParam(group1Ip1, group1Mac, groupEpc[1], 4)
	platformData2 := generatePlatformDataByParam(group2Ip1, group2Mac, groupEpc[2], 4)
	policy.UpdateInterfaceData([]PlatformData{platformData1, platformData2})
	generateIpgroupData(policy)
	generateAclData(policy)
	key := generateLookupKey(group1Mac, group2Mac, group1Ip1, group2Ip1, IPProtocolTCP, 0, 8000)
	setEthTypeAndOthers(key, EthernetTypeIPv4, ttl, l2EndBool[1], l2EndBool[1])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getEndpointData(policy, key)
	}
}

func BenchmarkGetDataByIp(b *testing.B) {
	policy := NewPolicyTable(1, 2, 1024, false)
	ip1 := generateIpNet(testIp1, 100, 32)
	data1 := generatePlatformDataByIp(groupEpc[1], testMac1, ip1)
	ip2 := generateIpNet(testIp2, 200, 24)
	data2 := generatePlatformDataByIp(groupEpc[2], testMac2, ip2)
	ip3 := generateIpNet(testIp3, 300, 16)
	data3 := generatePlatformDataByIp(groupEpc[3], testMac3, ip3)
	ip4 := generateIpNet(testIp4, 300, 8)
	data4 := generatePlatformDataByIp(groupEpc[4], testMac4, ip4)
	policy.UpdateInterfaceData([]PlatformData{data1, data2, data3, data4})
	for i := 0; i < b.N; i++ {
		policy.cloudPlatformLabeler.GetDataByIp(IpFromUint32(queryIp))
	}
}

func BenchmarkUpdateEndpointData(b *testing.B) {
	policy := NewPolicyTable(1, 2, 1024, false)
	ipGroup1 := generateIpGroup(group[11], groupEpc[0], ipNet10, ipNet11)
	policy.UpdateIpGroupData([]*IpGroupData{ipGroup1})
	ipNet := generateIpNet(group1Ip1, 123, 32)
	data1 := generatePlatformDataByIp(groupEpc[1], group1Mac, ipNet)
	policy.UpdateInterfaceData([]PlatformData{data1})
	key := generateLookupKey(group1Mac, group1Mac2, group1Ip1, group1Ip2, IPProtocolTCP, 50, 60)
	endpointData, _ := policy.lookupAllByKey(key)
	key.L3End0 = true
	key.L2End0 = true
	key.EthType = EthernetTypeARP
	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)
	for i := 0; i < b.N; i++ {
		policy.cloudPlatformLabeler.UpdateEndpointData(endpointStore, key)
	}
}
