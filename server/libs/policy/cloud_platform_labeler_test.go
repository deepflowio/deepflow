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
	"net"
	"testing"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

var (
	cidrSrcEpc = int32(10)
	cidrSrcMac = NewMACAddrFromString("11:11:11:11:11:11").Int()
	cidrSrcIp  = NewIPFromString("10.0.0.2").Int()
	cidrSrc    = "10.0.0.0/24"

	// 测试对等连接
	cidrPeerDstEpc = int32(20)
	cidrPeerDstIp  = NewIPFromString("192.168.0.2").Int()
	cidrPeerDst    = "192.168.0.2/24"

	// 测试私有网络内部路由
	cidrDstIp = NewIPFromString("10.0.0.3").Int()
)

func generateCidr(EpcId int32, cidrType uint8, ips string) *Cidr {
	_, ipNet, err := net.ParseCIDR(ips)
	if err != nil {
		return nil
	}

	return &Cidr{
		IpNet: ipNet,
		EpcId: EpcId,
		Type:  cidrType,
	}
}

func getCloudLabeler() *CloudPlatformLabeler {
	labeler := NewCloudPlatformLabeler(1, 1024)

	// platform
	platforms := make([]PlatformData, 0, 2)
	platform := generatePlatformDataByParam(cidrSrcIp, cidrSrcMac, cidrSrcEpc, 4)
	platforms = append(platforms, platform)
	labeler.UpdateInterfaceTable(platforms)

	// Peer Connection
	connections := make([]*PeerConnection, 0, 2)
	connection := generatePeerConnection(1, cidrSrcEpc, cidrPeerDstEpc)
	connections = append(connections, connection)
	labeler.UpdatePeerConnectionTable(connections)

	// cidr
	cidrs := make([]*Cidr, 0, 2)
	cidr := generateCidr(cidrPeerDstEpc, 1, cidrPeerDst)
	cidrs = append(cidrs, cidr)
	cidr = generateCidr(cidrSrcEpc, 1, cidrSrc)
	cidrs = append(cidrs, cidr)
	labeler.UpdateCidr(cidrs)

	return labeler
}

func TestCidr(t *testing.T) {
	labeler := getCloudLabeler()
	// 对等连接
	key := generateLookupKey(cidrSrcMac, 0, cidrSrcIp, cidrPeerDstIp, 0, 0, 0)
	endpointData := labeler.GetEndpointData(key)
	if endpointData.DstInfo.L3EpcId != cidrPeerDstEpc {
		t.Errorf("Dst L3EpcId error: %v", endpointData)
	}

	// 私有网络内部路由
	key = generateLookupKey(cidrSrcMac, 0, cidrSrcIp, cidrDstIp, 0, 0, 0)
	endpointData = labeler.GetEndpointData(key)
	if endpointData.DstInfo.L3EpcId != cidrSrcEpc {
		t.Errorf("Dst L3EpcId error: %v", endpointData)
	}
}

func TestEpcOrder(t *testing.T) {
	labeler := NewCloudPlatformLabeler(1, 1024)
	// platform
	platforms := make([]PlatformData, 0, 2)
	platform := generatePlatformDataByParam(cidrSrcIp, cidrSrcMac, cidrSrcEpc, 4) // EPC: 10
	platforms = append(platforms, platform)
	platform = generatePlatformDataByParam(cidrPeerDstIp, 0, cidrPeerDstEpc, 4) // EPC: 20
	platforms = append(platforms, platform)
	labeler.UpdateInterfaceTable(platforms)

	// cidr
	cidrs := make([]*Cidr, 0, 2)
	cidr := generateCidr(cidrSrcEpc, CIDR_TYPE_WAN, cidrPeerDst) // EPC: 10
	cidrs = append(cidrs, cidr)
	labeler.UpdateCidr(cidrs)

	key := generateLookupKey(cidrSrcMac, 0, cidrSrcIp, cidrPeerDstIp, 0, 0, 0)
	endpointData := labeler.GetEndpointData(key)
	if endpointData.DstInfo.L3EpcId != cidrSrcEpc {
		t.Errorf("Dst L3EpcId error: %v", endpointData)
	}

	// Peer Connection
	connections := make([]*PeerConnection, 0, 2)
	connection := generatePeerConnection(1, cidrSrcEpc, cidrPeerDstEpc) // Peer Epc: 10 <-> 20
	connections = append(connections, connection)
	labeler.UpdatePeerConnectionTable(connections)

	labeler.UpdateInterfaceTable(platforms)
	labeler.UpdateCidr(cidrs)
	key = generateLookupKey(cidrSrcMac, 0, cidrSrcIp, cidrPeerDstIp, 0, 0, 0)
	endpointData = labeler.GetEndpointData(key)
	// 加入对等连接后，对等连接查询优先级高于WAN
	if endpointData.DstInfo.L3EpcId != cidrPeerDstEpc {
		t.Errorf("Dst L3EpcId error: %v", endpointData)
	}

}
