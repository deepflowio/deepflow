package common

import (
	"time"

	"github.com/google/gopacket/layers"

	data "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet/app/common/doctime"
)

type Flow data.TaggedFlow

const (
	MAX_GROUP = 1 << 16
)

func IsOuterPublicIp(l3EpcId int32) bool {
	return l3EpcId == data.EPC_FROM_INTERNET
}

func (f *Flow) IsClosedFlow() bool {
	return f.CloseType != data.CloseTypeForcedReport
}

func (f *Flow) ClosedFlowCount() uint64 {
	if f.IsClosedFlow() {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) ClosedFlowDuration() time.Duration {
	if f.IsClosedFlow() {
		return f.Duration
	} else {
		return 0
	}
}

func (f *Flow) NewFlowCount() uint64 {
	if RoundToSecond(f.StartTime) == RoundToSecond(f.FlowMetricsPeers[data.FLOW_METRICS_PEER_SRC].ArrTime0) ||
		RoundToSecond(f.StartTime) == RoundToSecond(f.FlowMetricsPeers[data.FLOW_METRICS_PEER_DST].ArrTime0) {
		return 1
	}
	return 0
}

func (f *Flow) AbnormalFlowCount() uint64 {
	if f.Proto != layers.IPProtocolTCP {
		return 0
	}
	if !f.IsClosedFlow() {
		return 0
	}
	if f.CloseType == data.CloseTypeClientHalfClose || f.CloseType == data.CloseTypeServerHalfClose || f.CloseType == data.CloseTypeClientHalfOpen ||
		f.CloseType == data.CloseTypeServerHalfOpen || f.CloseType == data.CloseTypeTCPServerRst || f.CloseType == data.CloseTypeTCPClientRst {
		return 1
	}

	return 0
}

func (f *Flow) isHalfOpenFlow() bool {
	return f.CloseType == data.CloseTypeClientHalfOpen || f.CloseType == data.CloseTypeServerHalfOpen
}

func (f *Flow) HalfOpenFlowCount() uint64 {
	if f.isHalfOpenFlow() {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) RetransFlowCount() uint64 {
	if f.TcpPerfStats == nil {
		return 0
	}
	if f.TcpPerfCountsPeerSrc.RetransCount > 0 ||
		f.TcpPerfCountsPeerDst.RetransCount > 0 ||
		f.TcpPerfCountsPeerSrc.SynRetransCount > 0 ||
		f.TcpPerfCountsPeerDst.SynRetransCount > 0 {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) RetransCountSrc() uint32 {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.TcpPerfCountsPeerSrc.RetransCount
}

func (f *Flow) RetransCountDst() uint32 {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.TcpPerfCountsPeerDst.RetransCount
}

func (f *Flow) ZeroWinCountSrc() uint32 {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.TcpPerfCountsPeerSrc.ZeroWinCount
}

func (f *Flow) ZeroWinCountDst() uint32 {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.TcpPerfCountsPeerDst.ZeroWinCount
}

func (f *Flow) ClosedRTTSyn() time.Duration {
	if !f.IsClosedFlow() {
		return 0
	} else {
		return f.GetRTTSyn()
	}
}

func (f *Flow) ClosedRTTSynClient() time.Duration {
	if !f.IsClosedFlow() {
		return 0
	} else {
		return f.GetRTTSynClient()
	}
}

func (f *Flow) ClosedRTTSynServer() time.Duration {
	if !f.IsClosedFlow() {
		return 0
	} else {
		return f.GetRTTSynServer()
	}
}

func (f *Flow) RTTSynFlow() uint64 {
	if f.TcpPerfStats == nil {
		return 0
	}
	if f.IsClosedFlow() && f.RTTSyn != 0 {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) RTTSynClientFlow() uint64 {
	if f.TcpPerfStats == nil {
		return 0
	}
	if f.IsClosedFlow() && f.RTTSynClient != 0 {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) RTTFlow() uint64 {
	if f.TcpPerfStats == nil {
		return 0
	}
	if f.RTT != 0 {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) ARTFlow() uint64 {
	if f.TcpPerfStats == nil {
		return 0
	}
	if f.ART != 0 {
		return 1
	} else {
		return 0
	}
}

func (f *Flow) GetRTTSyn() time.Duration {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.RTTSyn
}

func (f *Flow) GetRTTSynClient() time.Duration {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.RTTSynClient
}

func (f *Flow) GetRTTSynServer() time.Duration {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.RTTSynServer
}

func (f *Flow) GetRTT() time.Duration {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.RTT
}

func (f *Flow) GetART() time.Duration {
	if f.TcpPerfStats == nil {
		return 0
	}
	return f.ART
}
