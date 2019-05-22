package perf

import (
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

var NODE_CODES = []outputtype.Code{}

var STAT_NODE_CODES_LEN = len(NODE_CODES)

var POLICY_NODE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.TAPType,
	outputtype.IndexToCode(0x01) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.TAPType,
}

var POLICY_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x02) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.TAPType,
}

var POLICY_NODE_CODE_LEN = len(POLICY_NODE_CODES)

var POLICY_GROUP_NODE_CODES = []outputtype.Code{}
var POLICY_GROUP_EDGE_CODES = []outputtype.Code{}

type FlowToPerfDocumentMapper struct {
	policyGroup []inputtype.AclAction

	docs      *utils.StructBuffer
	encoder   *codec.SimpleEncoder
	codes     []outputtype.Code
	aclGroups [2][]int32
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
	interestActionFlags := inputtype.ACTION_TCP_FLOW_PERF_COUNTING | inputtype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING
	if actionFlags&interestActionFlags == 0 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)

	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActionFlags)
	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, interestActionFlags, p.policyGroup)

	oneSideCodes := make([]outputtype.Code, 0, STAT_NODE_CODES_LEN)
	if actionFlags&inputtype.ACTION_TCP_FLOW_PERF_COUNTING != 0 {
		if statTemplates&inputtype.TEMPLATE_NODE != 0 {
			oneSideCodes = append(oneSideCodes, NODE_CODES...)
		}
	}

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2End := [2]bool{flow.FlowMetricsPeerSrc.IsL2End, flow.FlowMetricsPeerDst.IsL2End}
	isL3End := [2]bool{flow.FlowMetricsPeerSrc.IsL3End, flow.FlowMetricsPeerDst.IsL3End}
	packets := [2]uint64{flow.FlowMetricsPeerSrc.PacketCount, flow.FlowMetricsPeerDst.PacketCount}
	retransCnt := [2]uint32{flow.RetransCountSrc(), flow.RetransCountDst()}
	zeroWinCnt := [2]uint32{flow.ZeroWinCountSrc(), flow.ZeroWinCountDst()}

	docTimestamp := RoundToMinute(flow.StartTime)
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.PerfMeter{
			PerfMeterSum: outputtype.PerfMeterSum{
				SumFlowCount:         1,
				SumClosedFlowCount:   flow.ClosedFlowCount(),
				SumHalfOpenFlowCount: flow.HalfOpenFlowCount(),
				SumPacketTx:          packets[thisEnd],
				SumPacketRx:          packets[otherEnd],
				SumRetransCntTx:      uint64(retransCnt[thisEnd]),
				SumRetransCntRx:      uint64(retransCnt[otherEnd]),

				SumRTTSyn:     flow.ClosedRTTSyn(),
				SumRTTAvg:     flow.GetRTT(),
				SumARTAvg:     flow.GetART(),
				SumRTTSynFlow: flow.RTTSynFlow(),
				SumRTTAvgFlow: flow.RTTFlow(),
				SumARTAvgFlow: flow.ARTFlow(),

				SumZeroWndCntTx: uint64(zeroWinCnt[thisEnd]),
				SumZeroWndCntRx: uint64(zeroWinCnt[otherEnd]),
			},
			PerfMeterMax: outputtype.PerfMeterMax{
				MaxRTTSyn: flow.ClosedRTTSyn(),
				MaxRTTAvg: flow.GetRTT(),
				MaxARTAvg: flow.GetART(),
			},
			PerfMeterMin: outputtype.PerfMeterMin{
				MinRTTSyn: flow.ClosedRTTSyn(),
				MinRTTAvg: flow.GetRTT(),
				MinARTAvg: flow.GetART(),
			},
		}
		field := outputtype.Field{
			IP:           ips[thisEnd],
			TAPType:      TAPTypeFromInPort(flow.InPort),
			Direction:    directions[thisEnd],
			ACLDirection: outputtype.ACL_FORWARD, // 含ACLDirection字段时仅考虑ACL正向匹配

			IP1: ips[otherEnd],
		}

		// node
		for _, code := range oneSideCodes {
			if IsDupTraffic(flow.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
				continue
			}
			if IsWrongEndPoint(thisEnd, code) {
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
			doc.ActionFlags = uint32(inputtype.ACTION_TCP_FLOW_PERF_COUNTING)
		}

		// policy
		for _, policy := range p.policyGroup {
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			field.ACLGID = uint16(policy.GetACLGID())
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
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
				doc.ActionFlags = uint32(policy.GetActionFlags())
			}

			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧Tag
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧Tag
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
				doc.ActionFlags = uint32(policy.GetActionFlags())
			}

			flow.FillACLGroupID(policy, p.aclGroups[:])

			// group node
			codes = codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_GROUP_NODE_CODES...)
			}
			for _, code := range codes {
				for _, groupID := range p.aclGroups[thisEnd] {
					if groupID == 0 {
						continue
					}
					field.GroupID = int16(groupID)
					if IsDupTraffic(flow.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
						continue
					}
					if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
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
					doc.ActionFlags = uint32(policy.GetActionFlags())
				}
			}

			// group edge
			codes = codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_GROUP_EDGE_CODES...)
			}
			for _, code := range codes {
				for _, srcGroup := range p.aclGroups[thisEnd] {
					field.GroupID = int16(srcGroup)
					for _, dstGroup := range p.aclGroups[otherEnd] {
						field.GroupID1 = int16(dstGroup)
						if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧tag
							continue
						}
						if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧tag
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
						doc.ActionFlags = uint32(policy.GetActionFlags())
					}
				}
			}
		}
	}
	return p.docs.Slice()
}
