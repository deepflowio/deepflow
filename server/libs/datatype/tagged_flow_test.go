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

package datatype

import (
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
)

func TestTaggedFlowEncodeDecode(t *testing.T) {
	TunnelField := TunnelField{
		TxIP0: 100,
		TxIP1: 200,
		RxIP0: 200,
		RxIP1: 300,
		TxId:  102,
		RxId:  102,
		Type:  TUNNEL_TYPE_VXLAN,
	}

	FlowKey := FlowKey{
		VtapId:  200,
		TapType: 3,
		TapPort: FromLocalMAC(0, 201),
		MACSrc:  20000000002,
		MACDst:  20000000003,

		IPSrc:   204,
		IPDst:   205,
		IP6Src:  []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		IP6Dst:  []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		PortSrc: 206,
		PortDst: 207,
		Proto:   layers.IPProtocolTCP,
	}

	FlowM := FlowMetricsPeer{
		//	TickByteCount:    301,
		//	TickPacketCount:  302,
		ByteCount:        303,
		L3ByteCount:      310,
		L4ByteCount:      311,
		PacketCount:      304,
		TotalByteCount:   305,
		TotalPacketCount: 306,
		First:            307,
		Last:             308,
		L3EpcID:          312,
		TCPFlags:         222,
		IsL2End:          true,
		IsL3End:          false,
		IsActiveHost:     true,
	}

	tcpPerfCountsPeer := TcpPerfCountsPeer{
		RetransCount: 601,
		ZeroWinCount: 602,
	}

	TCPPerfStats := TCPPerfStats{
		TcpPerfCountsPeers: [2]TcpPerfCountsPeer{tcpPerfCountsPeer, tcpPerfCountsPeer},
		TotalRetransCount:  508,
	}

	Flow := Flow{
		FlowKey:          FlowKey,
		FlowMetricsPeers: [FLOW_METRICS_PEER_MAX]FlowMetricsPeer{FlowM, FlowM},
		Tunnel:           TunnelField,

		FlowID: 401,

		StartTime: 404,
		EndTime:   405,
		Duration:  406,
		//	PacketStatTime: 407,
		//	FlowStatTime:   408,

		// VLAN:    409,
		EthType: layers.EthernetTypeIPv4,

		FlowPerfStats:   &FlowPerfStats{L4Protocol: L4_PROTOCOL_TCP, TCPPerfStats: TCPPerfStats},
		CloseType:       CloseTypeTCPServerRst,
		IsActiveService: false,
		//	QueueHash:       104,
		//	IsNewFlow:       true,
	}

	ef := &TaggedFlow{
		Flow: Flow,
	}
	encoder := codec.AcquireSimpleEncoder()
	pbEncode := &pb.TaggedFlow{}
	ef.WriteToPB(pbEncode)
	encoder.WritePB(pbEncode)

	decoder := &codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	pbDecode := &pb.TaggedFlow{}
	decoder.ReadPB(pbDecode)

	if pbEncode.String() != pbDecode.String() {
		t.Errorf("flow encode和decode结果不一致 \nencode=%s  \ndecode=%s", pbEncode, pbDecode)
	}
}

func TestTaggedFlowEncodeDecodeiNul(t *testing.T) {
	FlowKey := FlowKey{
		IP6Src: []byte{},
		IP6Dst: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	}

	tcpPerfCountsPeer := TcpPerfCountsPeer{
		ZeroWinCount: 603,
	}

	TCPPerfStats := TCPPerfStats{
		TcpPerfCountsPeers: [2]TcpPerfCountsPeer{tcpPerfCountsPeer},
	}

	Flow := Flow{
		FlowKey:       FlowKey,
		FlowPerfStats: &FlowPerfStats{L4Protocol: L4_PROTOCOL_TCP, TCPPerfStats: TCPPerfStats},
	}

	ef := &TaggedFlow{
		Flow: Flow,
	}
	encoder := codec.AcquireSimpleEncoder()

	pbEncode := &pb.TaggedFlow{}
	ef.WriteToPB(pbEncode)
	encoder.WritePB(pbEncode)

	decoder := &codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	pbDecode := &pb.TaggedFlow{}
	decoder.ReadPB(pbDecode)

	if pbEncode.String() != pbDecode.String() {
		t.Errorf("flow encode和decode结果不一致 \nencode=%s  \ndecode=%s", pbEncode, pbDecode)
	}
}

func TestCloneTaggedFlow(t *testing.T) {
	FlowKey := FlowKey{
		IP6Src: []byte{},
		IP6Dst: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	}

	tcpPerfCountsPeer := TcpPerfCountsPeer{
		ZeroWinCount: 603,
	}

	TCPPerfStats := TCPPerfStats{
		TcpPerfCountsPeers: [2]TcpPerfCountsPeer{tcpPerfCountsPeer},
	}

	Flow := Flow{
		FlowKey:       FlowKey,
		FlowPerfStats: &FlowPerfStats{L4Protocol: L4_PROTOCOL_TCP, TCPPerfStats: TCPPerfStats},
	}

	ef := &TaggedFlow{
		Flow: Flow,
	}

	eff := CloneTaggedFlow(ef)
	if ef.String() != eff.String() {
		t.Error("CloneTaggedFlow()实现不正确")
	}
}

func TestTaggedFlowRelease(t *testing.T) {
	FlowKey := FlowKey{
		IP6Src: []byte{},
		IP6Dst: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	}

	tcpPerfCountsPeer := TcpPerfCountsPeer{
		ZeroWinCount: 603,
	}

	TCPPerfStats := TCPPerfStats{
		TcpPerfCountsPeers: [2]TcpPerfCountsPeer{tcpPerfCountsPeer},
	}

	Flow := Flow{
		FlowKey:       FlowKey,
		FlowPerfStats: &FlowPerfStats{L4Protocol: L4_PROTOCOL_TCP, TCPPerfStats: TCPPerfStats},
	}

	f := &TaggedFlow{
		Flow: Flow,
	}
	ff := &TaggedFlow{}
	f.Release()

	if f.String() != ff.String() {
		t.Error("Release()实现不正确")
	}
}

// FIXME: 测试SequencialMerge和Reverse
