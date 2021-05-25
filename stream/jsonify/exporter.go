package jsonify

import (
	"github.com/gogo/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet/stream/jsonify/dfi"
)

func NewDataLinkLayer(f *FlowLogger) *dfi.DataLinkLayer {
	return &dfi.DataLinkLayer{
		Mac_0:   proto.Uint64(f.MAC0),
		Mac_1:   proto.Uint64(f.MAC1),
		EthType: proto.Uint32(uint32(f.EthType)),
		Vlan:    proto.Uint32(uint32(f.VLAN)),
	}
}

func NewNetworkLayer(f *FlowLogger) *dfi.NetworkLayer {
	return &dfi.NetworkLayer{
		Ip4_0:         proto.Uint32(f.IP40),
		Ip4_1:         proto.Uint32(f.IP41),
		Ip6_0:         f.IP60,
		Ip6_1:         f.IP61,
		IsIpv4:        proto.Bool(f.IsIPv4),
		Protocol:      proto.Uint32(uint32(f.Protocol)),
		TunnelTier:    proto.Uint32(uint32(f.TunnelTier)),
		TunnelType:    proto.Uint32(uint32(f.TunnelType)),
		TunnelTxId:    proto.Uint32(f.TunnelTxID),
		TunnelRxId:    proto.Uint32(f.TunnelRxID),
		TunnelTxIp4_0: proto.Uint32(f.TunnelTxIP40),
		TunnelTxIp4_1: proto.Uint32(f.TunnelTxIP41),
		TunnelRxIp4_0: proto.Uint32(f.TunnelRxIP40),
		TunnelRxIp4_1: proto.Uint32(f.TunnelRxIP41),
		TunnelTxIp6_0: f.TunnelTxIP60,
		TunnelTxIp6_1: f.TunnelTxIP61,
		TunnelRxIp6_0: f.TunnelRxIP60,
		TunnelRxIp6_1: f.TunnelRxIP61,
		TunnelIsIpv4:  proto.Bool(f.TunnelIsIPv4),
	}
}

func NewTransportLayer(f *FlowLogger) *dfi.TransportLayer {
	return &dfi.TransportLayer{
		ClientPort:    proto.Uint32(uint32(f.ClientPort)),
		ServerPort:    proto.Uint32(uint32(f.ServerPort)),
		TcpFlagsBit_0: proto.Uint32(uint32(f.TCPFlagsBit0)),
		TcpFlagsBit_1: proto.Uint32(uint32(f.TCPFlagsBit1)),
	}
}

func NewApplicationLayer(f *FlowLogger) *dfi.ApplicationLayer {
	return &dfi.ApplicationLayer{
		L7Protocol: proto.Uint32(uint32(f.L7Protocol)),
	}
}

func NewInternet(f *FlowLogger) *dfi.Internet {
	return &dfi.Internet{
		Province_0: proto.String(f.Province0),
		Province_1: proto.String(f.Province1),
	}
}

func NewKnowledgeGraph(f *KnowledgeGraph) *dfi.KnowledgeGraph {
	return &dfi.KnowledgeGraph{
		RegionId_0:     proto.Uint32(uint32(f.RegionID0)),
		RegionId_1:     proto.Uint32(uint32(f.RegionID1)),
		AzId_0:         proto.Uint32(uint32(f.AZID0)),
		AzId_1:         proto.Uint32(uint32(f.AZID1)),
		HostId_0:       proto.Uint32(uint32(f.HostID0)),
		HostId_1:       proto.Uint32(uint32(f.HostID1)),
		L3DeviceType_0: proto.Uint32(uint32(f.L3DeviceType0)),
		L3DeviceType_1: proto.Uint32(uint32(f.L3DeviceType1)),
		L3DeviceId_0:   proto.Uint32(f.L3DeviceID0),
		L3DeviceId_1:   proto.Uint32(f.L3DeviceID1),
		PodNodeId_0:    proto.Uint32(f.PodNodeID0),
		PodNodeId_1:    proto.Uint32(f.PodNodeID1),
		PodNsId_0:      proto.Uint32(uint32(f.PodNSID0)),
		PodNsId_1:      proto.Uint32(uint32(f.PodNSID1)),
		PodGroupId_0:   proto.Uint32(f.PodGroupID0),
		PodGroupId_1:   proto.Uint32(f.PodGroupID1),
		PodId_0:        proto.Uint32(f.PodID0),
		PodId_1:        proto.Uint32(f.PodID1),
		PodClusterId_0: proto.Uint32(uint32(f.PodClusterID0)),
		PodClusterId_1: proto.Uint32(uint32(f.PodClusterID1)),
		L3EpcId_0:      proto.Int32(f.L3EpcID0),
		L3EpcId_1:      proto.Int32(f.L3EpcID1),
		EpcId_0:        proto.Int32(f.EpcID0),
		EpcId_1:        proto.Int32(f.EpcID1),
		SubnetId_0:     proto.Uint32(uint32(f.SubnetID0)),
		SubnetId_1:     proto.Uint32(uint32(f.SubnetID1)),
	}
}

func NewFlowInfo(f *FlowLogger) *dfi.FlowInfo {
	return &dfi.FlowInfo{
		CloseType:  proto.Uint32(uint32(f.CloseType)),
		FlowSource: proto.Uint32(uint32(f.FlowSource)),
		FlowIdStr:  proto.Uint64(f.FlowIDStr),
		TapType:    proto.Uint32(uint32(f.TapType)),
		TapPort:    proto.Uint32(f.TapPort),
		VtapId:     proto.Uint32(uint32(f.VtapID)),
		L2End_0:    proto.Bool(f.L2End0),
		L2End_1:    proto.Bool(f.L2End1),
		L3End_0:    proto.Bool(f.L3End0),
		L3End_1:    proto.Bool(f.L3End1),
		StartTime:  proto.Uint32(f.StartTime),
		EndTime:    proto.Uint32(f.FlowInfo.EndTime),
		Duration:   proto.Uint64(f.Duration),
	}
}

func NewMetrics(f *FlowLogger) *dfi.Metrics {
	return &dfi.Metrics{
		PacketTx:        proto.Uint64(f.PacketTx),
		PacketRx:        proto.Uint64(f.PacketRx),
		ByteTx:          proto.Uint64(f.ByteTx),
		ByteRx:          proto.Uint64(f.ByteRx),
		L3ByteTx:        proto.Uint64(f.L3ByteTx),
		L3ByteRx:        proto.Uint64(f.L3ByteRx),
		L4ByteTx:        proto.Uint64(f.L4ByteTx),
		L4ByteRx:        proto.Uint64(f.L4ByteRx),
		TotalPacketTx:   proto.Uint64(f.TotalPacketTx),
		TotalPacketRx:   proto.Uint64(f.TotalPacketRx),
		TotalByteTx:     proto.Uint64(f.TotalByteTx),
		TotalByteRx:     proto.Uint64(f.TotalByteRx),
		L7Request:       proto.Uint32(f.L7Request),
		L7Response:      proto.Uint32(f.L7Response),
		Rtt:             proto.Uint32(f.RTT),
		RttClientSum:    proto.Uint32(f.RTTClientSum),
		RttServerSum:    proto.Uint32(f.RTTServerSum),
		SrtSum:          proto.Uint32(f.SRTSum),
		ArtSum:          proto.Uint32(f.ARTSum),
		RrtSum:          proto.Uint64(f.RRTSum),
		RttClientCount:  proto.Uint32(f.RTTClientCount),
		RttServerCount:  proto.Uint32(f.RTTServerCount),
		SrtCount:        proto.Uint32(f.SRTCount),
		ArtCount:        proto.Uint32(f.ARTCount),
		RrtCount:        proto.Uint32(f.RRTCount),
		RttClientMax:    proto.Uint32(f.RTTClientMax),
		RttServerMax:    proto.Uint32(f.RTTServerMax),
		SrtMax:          proto.Uint32(f.SRTMax),
		ArtMax:          proto.Uint32(f.ARTMax),
		RrtMax:          proto.Uint32(f.RRTMax),
		RetransTx:       proto.Uint32(f.RetransTx),
		RetransRx:       proto.Uint32(f.RetransRx),
		ZeroWinTx:       proto.Uint32(f.ZeroWinTx),
		ZeroWinRx:       proto.Uint32(f.ZeroWinRx),
		L7ClientError:   proto.Uint32(f.L7ClientError),
		L7ServerError:   proto.Uint32(f.L7ServerError),
		L7ServerTimeout: proto.Uint32(f.L7ServerTimeout),
	}
}

func NewDfiL4Flow(f *FlowLogger) *dfi.L4Flow {
	l4Flow := &dfi.L4Flow{
		DataLinkLayer:    NewDataLinkLayer(f),
		NetworkLayer:     NewNetworkLayer(f),
		ApplicationLayer: NewApplicationLayer(f),
		Internet:         NewInternet(f),
		KnowledgeGraph:   NewKnowledgeGraph(&f.KnowledgeGraph),
		Flowinfo:         NewFlowInfo(f),
		Metrics:          NewMetrics(f),
	}
	return l4Flow
}

func NewL7Base(f *L7Base) *dfi.L7Base {
	return &dfi.L7Base{
		Ip4_0:          proto.Uint32(f.IP40),
		Ip4_1:          proto.Uint32(f.IP41),
		Ip6_0:          f.IP60,
		Ip6_1:          f.IP61,
		IsIpv4:         proto.Bool(f.IsIPv4),
		ClientPort:     proto.Uint32(uint32(f.ClientPort)),
		ServerPort:     proto.Uint32(uint32(f.ServerPort)),
		KnowledgeGraph: NewKnowledgeGraph(&f.KnowledgeGraph),
		FlowIdStr:      proto.Uint64(f.FlowIDStr),
		TapType:        proto.Uint32(uint32(f.TapType)),
		TapPort:        proto.Uint32(f.TapPort),
		VtapId:         proto.Uint32(uint32(f.VtapID)),
		Timestamp:      proto.Uint64(f.Timestamp),
	}
}

func NewDfiL7HTTP(f *HTTPLogger) *dfi.L7HTTP {
	return &dfi.L7HTTP{
		Base:          NewL7Base(&f.L7Base),
		Type:          proto.Uint32(uint32(f.Type)),
		Version:       proto.Uint32(uint32(f.Version)),
		Method:        proto.String(f.Method),
		ClientIp4:     proto.Uint32(f.ClientIP4),
		ClientIp6:     f.ClientIP6,
		ClientIsIpv4:  proto.Bool(f.ClientIsIPv4),
		Host:          proto.String(f.Host),
		Path:          proto.String(f.Path),
		StreamId:      proto.Uint32(f.StreamID),
		TraceId:       proto.String(f.TraceID),
		StatusCode:    proto.Uint32(uint32(f.StatusCode)),
		ContentLength: proto.Int64(f.ContentLength),
		Duration:      proto.Uint64(f.Duration),
	}
}

func NewDfiL7DNS(f *DNSLogger) *dfi.L7DNS {
	return &dfi.L7DNS{
		Base:       NewL7Base(&f.L7Base),
		Type:       proto.Uint32(uint32(f.Type)),
		Id:         proto.Uint32(uint32(f.ID)),
		DomainName: proto.String(f.DomainName),
		QueryType:  proto.Uint32(uint32(f.QueryType)),
		AnswerCode: proto.Uint32(uint32(f.AnswerCode)),
		AnswerAddr: proto.String(f.AnswerAddr),
		Duration:   proto.Uint64(f.Duration),
	}
}

func MarshalL4Flow(f *FlowLogger, bytes *utils.ByteBuffer) error {
	flow := &dfi.Flow{
		Type:   dfi.FlowType_L4FlowType.Enum(),
		L4Flow: NewDfiL4Flow(f),
	}
	buf := bytes.Use(flow.Size())
	if _, err := flow.MarshalTo(buf); err != nil {
		return err
	}
	return nil
}

func MarshalL7HTTP(f *HTTPLogger, bytes *utils.ByteBuffer) error {
	flow := &dfi.Flow{
		Type:   dfi.FlowType_L4FlowType.Enum(),
		L7Http: NewDfiL7HTTP(f),
	}
	buf := bytes.Use(flow.Size())
	if _, err := flow.MarshalTo(buf); err != nil {
		return err
	}
	return nil
}

func MarshalL7DNS(f *DNSLogger, bytes *utils.ByteBuffer) error {
	flow := &dfi.Flow{
		Type:  dfi.FlowType_L4FlowType.Enum(),
		L7Dns: NewDfiL7DNS(f),
	}
	buf := bytes.Use(flow.Size())
	if _, err := flow.MarshalTo(buf); err != nil {
		return err
	}
	return nil
}
