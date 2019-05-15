package consolelog

import (
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	. "gitlab.x.lan/yunshan/droplet/app/common/docbuffer"
	. "gitlab.x.lan/yunshan/droplet/app/common/doctime"
	. "gitlab.x.lan/yunshan/droplet/app/common/endpoint"
	. "gitlab.x.lan/yunshan/droplet/app/common/flow"
)

var CODES = []outputtype.Code{}

type FlowToConsoleLogDocumentMapper struct {
	docs    *utils.StructBuffer
	encoder *codec.SimpleEncoder
}

func (p *FlowToConsoleLogDocumentMapper) GetName() string {
	return "FlowToConsoleLogDocumentMapper"
}

func NewProcessor() app.FlowProcessor {
	return &FlowToConsoleLogDocumentMapper{}
}

func (p *FlowToConsoleLogDocumentMapper) Prepare() {
	p.docs = NewMeterSharedDocBuffer()
	p.encoder = &codec.SimpleEncoder{}
}

func (p *FlowToConsoleLogDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	return p.docs.Slice() // v5.5.3弃用

	p.docs.Reset()

	if rawFlow.Proto != layers.IPProtocolTCP {
		return p.docs.Slice()
	}
	if rawFlow.PolicyData.ActionFlags&inputtype.ACTION_FLOW_MISC_COUNTING == 0 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)
	if !flow.IsClosedFlow() {
		return p.docs.Slice()
	}
	if flow.ServiceNotAlive() {
		return p.docs.Slice()
	}
	if flow.PortDst != 22 && flow.PortDst != 23 && flow.PortDst != 3389 { // SSH, Telnet, RDP
		return p.docs.Slice()
	}

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2End := [2]bool{flow.FlowMetricsPeerSrc.IsL2End, flow.FlowMetricsPeerDst.IsL2End}
	isL3End := [2]bool{flow.FlowMetricsPeerSrc.IsL3End, flow.FlowMetricsPeerDst.IsL3End}
	packets := [2]uint64{flow.FlowMetricsPeerSrc.TotalPacketCount, flow.FlowMetricsPeerDst.TotalPacketCount} // 由于仅统计ClosedFlow，这里用Total
	docTimestamp := RoundToMinute(flow.StartTime)

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO} { // 总是Edge组合、总会有ServerPort，只考虑服务端
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.ConsoleLogMeter{
			SumClosedFlowCount:    flow.ClosedFlowCount(),
			SumClosedFlowDuration: uint64(flow.ClosedFlowDuration() / time.Millisecond), // ms
			SumPacketTx:           packets[thisEnd],
			SumPacketRx:           packets[otherEnd],
		}

		field := outputtype.Field{
			Direction:  outputtype.ClientToServer,
			IP:         ips[thisEnd],
			IP1:        ips[otherEnd],
			L3EpcID:    int16(l3EpcIDs[thisEnd]),
			L3EpcID1:   int16(l3EpcIDs[otherEnd]),
			TAPType:    TAPTypeFromInPort(flow.InPort),
			ServerPort: flow.PortDst,
		}

		for _, code := range CODES {
			if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧Tag
				continue
			}
			tag := &outputtype.Tag{Field: &field, Code: code}
			if code.PossibleDuplicate() {
				id := tag.GetID(p.encoder)
				if _, exists := docMap[id]; exists {
					continue
				}
				docMap[id] = true
			}
			doc := p.docs.Get().(*app.Document)
			doc.Timestamp = docTimestamp
			field.FillTag(code, doc.Tag.(*outputtype.Tag))
			doc.Tag.SetID(tag.GetID(p.encoder))
			doc.Meter = &meter
		}
	}
	return p.docs.Slice()
}
