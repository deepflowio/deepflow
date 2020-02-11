package logusage

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
	"net"
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

	if !(rawFlow.EthType == layers.EthernetTypeIPv4 || rawFlow.EthType == layers.EthernetTypeIPv6) {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)
	flowMetricsPeerSrc := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_FLOW_COUNTING // 目前没有告警
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}
	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActions)
	if statTemplates&inputtype.TEMPLATE_EDGE_PORT_ALL == 0 { // LogXXX仅做四维统计
		return p.docs.Slice()
	}

	l3EpcIDs := [2]int32{flowMetricsPeerSrc.L3EpcID, flowMetricsPeerDst.L3EpcID}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	ip6s := [2]net.IP{flow.IP6Src, flow.IP6Dst}
	isL2L3End := [2]bool{
		flowMetricsPeerSrc.IsL2End && flowMetricsPeerSrc.IsL3End,
		flowMetricsPeerDst.IsL2End && flowMetricsPeerDst.IsL3End,
	}
	docTimestamp := RoundToMinute(flow.StartTime)
	packets := [2]uint64{flowMetricsPeerSrc.PacketCount, flowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flowMetricsPeerSrc.ByteCount << 3, flowMetricsPeerDst.ByteCount << 3}

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) { // FIXME: 可能要去掉
			ips[i] = 0
			ip6s[i] = net.IPv6zero
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
			TAPType:    TAPTypeFromInPort(flow.InPort),
			L3EpcID:    int16(l3EpcIDs[thisEnd]),
			Protocol:   flow.Proto,
			ServerPort: flow.PortDst,

			L3EpcID1: int16(l3EpcIDs[otherEnd]),
		}
		if flow.EthType == layers.EthernetTypeIPv4 {
			field.IsIPv6 = 0
			field.IP = ips[thisEnd]
			field.IP1 = ips[otherEnd]
		} else {
			field.IsIPv6 = 1
			field.IP6 = ip6s[thisEnd]
			field.IP61 = ip6s[otherEnd]
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
