package logusage

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
	"sync"

	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	. "gitlab.x.lan/yunshan/droplet/app/common/docbuffer"
	. "gitlab.x.lan/yunshan/droplet/app/common/doctime"
	. "gitlab.x.lan/yunshan/droplet/app/common/endpoint"
	. "gitlab.x.lan/yunshan/droplet/app/common/flow"
	. "gitlab.x.lan/yunshan/droplet/app/common/policy"
)

var log = logging.MustGetLogger("log_usage")

const (
	CODES_LEN = 64
)

type FlowToLogUsageDocumentMapper struct {
	pool *sync.Pool

	docs    *utils.StructBuffer
	encoder *codec.SimpleEncoder
}

func (p *FlowToLogUsageDocumentMapper) GetName() string {
	return "FlowToLogUsageDocumentMapper"
}

func NewProcessor() app.FlowProcessor {
	return &FlowToLogUsageDocumentMapper{}
}

func (p *FlowToLogUsageDocumentMapper) Prepare() {
	p.docs = NewMeterSharedDocBuffer()
	p.encoder = &codec.SimpleEncoder{}

}

func (p *FlowToLogUsageDocumentMapper) appendDoc(timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.LogUsageMeter, actionFlags uint32) {
	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *FlowToLogUsageDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()

	if rawFlow.EthType != layers.EthernetTypeIPv4 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_FLOW_COUNTING // 目前没有告警
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}
	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActions)
	if statTemplates&inputtype.TEMPLATE_EDGE_PORT_ALL == 0 { // LogXXX仅做四维统计
		return p.docs.Slice()
	}

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2L3End := [2]bool{
		flow.FlowMetricsPeerSrc.IsL2End && flow.FlowMetricsPeerSrc.IsL3End,
		flow.FlowMetricsPeerDst.IsL2End && flow.FlowMetricsPeerDst.IsL3End,
	}
	docTimestamp := RoundToMinute(flow.StartTime)
	packets := [2]uint64{flow.FlowMetricsPeerSrc.PacketCount, flow.FlowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flow.FlowMetricsPeerSrc.ByteCount << 3, flow.FlowMetricsPeerDst.ByteCount << 3}

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) { // FIXME: 可能要去掉
			ips[i] = 0
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.LogUsageMeter{
			SumPacketTx: packets[thisEnd],
			SumPacketRx: packets[otherEnd],
			SumBitTx:    bits[thisEnd],
			SumBitRx:    bits[otherEnd],
		}
		field := outputtype.Field{
			IP:         ips[thisEnd],
			TAPType:    TAPTypeFromInPort(flow.InPort),
			L3EpcID:    int16(l3EpcIDs[thisEnd]),
			Protocol:   flow.Proto,
			ServerPort: flow.PortDst,

			L3EpcID1: int16(l3EpcIDs[otherEnd]),
			IP1:      ips[otherEnd],
		}

		for _, code := range EDGE_PORT_CODES {
			if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
				continue
			}
			if IsWrongEndPoint(thisEnd, code) { // 双侧Tag
				continue
			}
			p.appendDoc(docTimestamp, &field, code, &meter, uint32(inputtype.ACTION_FLOW_COUNTING))
		}
	}
	return p.docs.Slice()
}
