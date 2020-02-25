package perf

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
	"net"

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

	"github.com/google/gopacket/layers"
)

const (
	CODES_LEN  = 64
	GROUPS_LEN = 16
)

// 注意：仅统计TCP流

type FlowToPerfDocumentMapper struct {
	policyGroup []inputtype.AclAction

	docs      *utils.StructBuffer
	encoder   *codec.SimpleEncoder
	codes     []outputtype.Code
	aclGroups [2][]int32

	fields [2]outputtype.Field
}

func (p *FlowToPerfDocumentMapper) GetName() string {
	return "FlowToPerfDocumentMapper"
}

func NewProcessor() app.FlowProcessor {
	return &FlowToPerfDocumentMapper{}
}

func (p *FlowToPerfDocumentMapper) Prepare() {
	p.policyGroup = make([]inputtype.AclAction, 0)

	p.docs = NewMeterSharedDocBuffer()
	p.encoder = &codec.SimpleEncoder{}
	p.codes = make([]outputtype.Code, 0, CODES_LEN)
	p.aclGroups = [2][]int32{make([]int32, 0, GROUPS_LEN), make([]int32, 0, GROUPS_LEN)}
}

func (p *FlowToPerfDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()
	if rawFlow.Proto != layers.IPProtocolTCP || rawFlow.TcpPerfStats == nil {
		return p.docs.Slice()
	}

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActionFlags := inputtype.ACTION_TCP_FLOW_PERF_COUNTING
	if actionFlags&interestActionFlags == 0 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)
	flowMetricsPeerSrc := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]

	statTemplates := GetTagTemplateByActionFlags(&rawFlow.PolicyData, interestActionFlags)
	p.policyGroup = FillPolicyTagTemplate(&rawFlow.PolicyData, interestActionFlags, p.policyGroup)

	oneSideCodes := make([]outputtype.Code, 0, NODE_CODES_LEN)
	if statTemplates&inputtype.TEMPLATE_NODE != 0 {
		oneSideCodes = append(oneSideCodes, NODE_CODES...)
	}

	l3EpcIDs := [2]int32{flowMetricsPeerSrc.L3EpcID, flowMetricsPeerDst.L3EpcID}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	ip6s := [2]net.IP{flow.IP6Src, flow.IP6Dst}
	isL2L3End := [2]bool{
		flowMetricsPeerSrc.IsL2End && flowMetricsPeerSrc.IsL3End,
		flowMetricsPeerDst.IsL2End && flowMetricsPeerDst.IsL3End,
	}
	packets := [2]uint64{flowMetricsPeerSrc.PacketCount, flowMetricsPeerDst.PacketCount}
	retransCnt := [2]uint32{flow.RetransCountSrc(), flow.RetransCountDst()}
	zeroWinCnt := [2]uint32{flow.ZeroWinCountSrc(), flow.ZeroWinCountDst()}

	docTimestamp := RoundToMinute(flow.StartTime)
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}

	isActiveHost := [2]bool{flowMetricsPeerSrc.IsActiveHost, flowMetricsPeerDst.IsActiveHost}
	for i := range ips {
		if !isActiveHost[i] || IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
			ip6s[i] = net.IPv6zero
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.PerfMeter{
			PerfMeterSum: outputtype.PerfMeterSum{
				SumFlowCount:         1,
				SumNewFlowCount:      flow.NewFlowCount(),
				SumClosedFlowCount:   flow.ClosedFlowCount(),
				SumHalfOpenFlowCount: flow.HalfOpenFlowCount(),
				SumPacketTx:          packets[thisEnd],
				SumPacketRx:          packets[otherEnd],
				SumRetransCntTx:      uint64(retransCnt[thisEnd]),
				SumRetransCntRx:      uint64(retransCnt[otherEnd]),

				SumRTTSyn:     flow.GetRTTSyn(),
				SumRTTAvg:     flow.GetRTT(),
				SumARTAvg:     flow.GetART(),
				SumRTTSynFlow: flow.RTTSynFlow(),
				SumRTTAvgFlow: flow.RTTFlow(),
				SumARTAvgFlow: flow.ARTFlow(),

				SumZeroWndCntTx: uint64(zeroWinCnt[thisEnd]),
				SumZeroWndCntRx: uint64(zeroWinCnt[otherEnd]),
			},
			PerfMeterMax: outputtype.PerfMeterMax{
				MaxRTTSyn:       flow.GetRTTSyn(),
				MaxRTTAvg:       flow.GetRTT(),
				MaxARTAvg:       flow.GetART(),
				MaxRTTSynClient: flow.GetRTTSynClient(),
				MaxRTTSynServer: flow.GetRTTSynServer(),
			},
		}

		field := &p.fields[thisEnd]
		if flow.EthType == layers.EthernetTypeIPv4 {
			field.IsIPv6 = 0
			field.IP = ips[thisEnd]
			field.IP1 = ips[otherEnd]
		} else {
			field.IsIPv6 = 1
			field.IP6 = ip6s[thisEnd]
			field.IP61 = ip6s[otherEnd]
		}
		field.TAPType = TAPTypeFromInPort(flow.InPort)
		field.Direction = directions[thisEnd]
		field.Protocol = flow.Proto
		field.ServerPort = flow.PortDst
		field.ACLDirection = outputtype.ACL_FORWARD // 含ACLDirection字段时仅考虑ACL正向匹配

		// node
		for _, code := range oneSideCodes {
			if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
				continue
			}
			if IsWrongEndPoint(thisEnd, code) {
				continue
			}
			doc := p.docs.Get().(*app.Document)
			doc.Timestamp = docTimestamp
			field.FillTag(code, doc.Tag.(*outputtype.Tag))
			doc.Meter = &meter
			doc.ActionFlags = uint32(inputtype.ACTION_TCP_FLOW_PERF_COUNTING)
		}

		// policy
		for _, policy := range p.policyGroup {
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			field.ACLGID = uint16(policy.GetACLGID())
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				doc := p.docs.Get().(*app.Document)
				doc.Timestamp = docTimestamp
				field.FillTag(code, doc.Tag.(*outputtype.Tag))
				doc.Meter = &meter
				doc.ActionFlags = uint32(policy.GetActionFlags())
			}

			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_EDGE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧Tag
					continue
				}
				doc := p.docs.Get().(*app.Document)
				doc.Timestamp = docTimestamp
				field.FillTag(code, doc.Tag.(*outputtype.Tag))
				doc.Meter = &meter
				doc.ActionFlags = uint32(policy.GetActionFlags())
			}
		}
	}
	return p.docs.Slice()
}
