package datatype

import (
	"testing"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

func TestTaggedFlowEncodeDecode(t *testing.T) {
	TunnelInfo := TunnelInfo{
		Src:  100,
		Dst:  101,
		Id:   102,
		Type: TUNNEL_TYPE_VXLAN,
	}

	FlowKey := FlowKey{
		TunnelInfo: TunnelInfo,
		VtapId:     200,
		TapType:    3,
		TapPort:    201,
		MACSrc:     20000000002,
		MACDst:     20000000003,

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

		FlowID:   401,
		Exporter: 403,

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
	ef.Encode(encoder)

	decoder := &codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	df := &TaggedFlow{}
	df.Decode(decoder)

	if ef.String() != df.String() {
		t.Errorf("flow encode和decode结果不一致 \nencode=%s  \ndecode=%s", ef, df)
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
	ef.Encode(encoder)

	decoder := &codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	df := &TaggedFlow{}
	df.Decode(decoder)

	if ef.String() != df.String() {
		t.Errorf("flow encode和decode结果不一致 \nencode=%s  \ndecode=%s", ef, df)
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
