package flowtype

import (
	"time"

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
	logging "github.com/op/go-logging"
)

// 注意：仅统计TCP流

var log = logging.MustGetLogger("flowtype")

const (
	CODES_LEN  = 64
	GROUPS_LEN = 16
)

// node

var NODE_CODES = []outputtype.Code{}

// policy node

var POLICY_NODE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.TAPType,
	outputtype.IndexToCode(0x01) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.TAPType,
}

var POLICY_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x02) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.TAPType,
}

var POLICY_NODE_CODES_LEN = len(POLICY_NODE_CODES)

// policy group

var POLICY_GROUP_NODE_CODES = []outputtype.Code{}

var POLICY_GROUP_NODE_CODES_LEN = len(POLICY_GROUP_NODE_CODES)

// policy group edge

var POLICY_GROUP_EDGE_CODES = []outputtype.Code{}

var POLICY_GROUP_EDGE_CODES_LEN = len(POLICY_GROUP_EDGE_CODES)

type FlowToTypeDocumentMapper struct {
	policyGroup []inputtype.AclAction

	docs      *utils.StructBuffer
	encoder   *codec.SimpleEncoder
	codes     []outputtype.Code
	aclGroups [2][]int32
}

func (p *FlowToTypeDocumentMapper) GetName() string {
	return "FlowToTypeDocumentMapper"
}

func NewProcessor() app.FlowProcessor {
	return &FlowToTypeDocumentMapper{}
}

func (p *FlowToTypeDocumentMapper) Prepare() {
	p.docs = NewMeterSharedDocBuffer()
	p.policyGroup = make([]inputtype.AclAction, 0)
	p.encoder = &codec.SimpleEncoder{}
	p.codes = make([]outputtype.Code, 0, CODES_LEN)
	p.aclGroups = [2][]int32{make([]int32, 0, GROUPS_LEN), make([]int32, 0, GROUPS_LEN)}
}

func (p *FlowToTypeDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()

	if rawFlow.Proto != layers.IPProtocolTCP {
		return p.docs.Slice()
	}
	interestActionFlags := inputtype.ACTION_FLOW_MISC_COUNTING
	if rawFlow.PolicyData.ActionFlags&interestActionFlags == 0 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)
	if !flow.IsClosedFlow() {
		return p.docs.Slice()
	}

	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActionFlags)
	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, interestActionFlags, p.policyGroup)

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2End := [2]bool{flow.FlowMetricsPeerSrc.IsL2End, flow.FlowMetricsPeerDst.IsL2End}
	isL3End := [2]bool{flow.FlowMetricsPeerSrc.IsL3End, flow.FlowMetricsPeerDst.IsL3End}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	bytes := flow.FlowMetricsPeerSrc.TotalByteCount + flow.FlowMetricsPeerDst.TotalByteCount // 由于仅统计ClosedFlow，这里用Total
	docTimestamp := RoundToMinute(flow.StartTime)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.TypeMeter{}

		switch { // FIXME: 三个switch case待确认
		case flow.Duration < time.Second:
			meter.SumCountL0S1S = 1
		case flow.Duration < 5*time.Second:
			meter.SumCountL1S5S = 1
		case flow.Duration < 10*time.Second:
			meter.SumCountL5S10S = 1
		case flow.Duration < time.Minute:
			meter.SumCountL10S1M = 1
		case flow.Duration < time.Hour:
			meter.SumCountL1M1H = 1
		default:
			meter.SumCountL1H = 1
		}

		switch {
		case bytes < 10e3:
			meter.SumCountE0K10K = 1
		case bytes < 100e3:
			meter.SumCountE10K100K = 1
		case bytes < 1e6:
			meter.SumCountE100K1M = 1
		case bytes < 100e6:
			meter.SumCountE1M100M = 1
		case bytes < 1e9:
			meter.SumCountE100M1G = 1
		default:
			meter.SumCountE1G = 1
		}

		switch flow.CloseType {
		case inputtype.CloseTypeTCPServerRst:
			meter.SumCountTServerRst = 1
		case inputtype.CloseTypeTCPClientRst:
			meter.SumCountTClientRst = 1
		case inputtype.CloseTypeServerHalfOpen:
			meter.SumCountTServerHalfOpen = 1
		case inputtype.CloseTypeClientHalfOpen:
			meter.SumCountTClientHalfOpen = 1
		case inputtype.CloseTypeServerHalfClose:
			meter.SumCountTServerHalfClose = 1
		case inputtype.CloseTypeClientHalfClose:
			meter.SumCountTClientHalfClose = 1
		}
		field := outputtype.Field{
			IP:           ips[thisEnd],
			TAPType:      TAPTypeFromInPort(flow.InPort),
			Direction:    directions[thisEnd],
			ACLDirection: outputtype.ACL_FORWARD, // 含ACLDirection字段时仅考虑ACL正向匹配

			IP1: ips[otherEnd],
		}

		// node
		if statTemplates&inputtype.TEMPLATE_NODE != 0 {
			for _, code := range NODE_CODES {
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
			}
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
			}

			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			for _, code := range codes {
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
			}

			flow.FillACLGroupID(policy, p.aclGroups[:])

			// group
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
					}
				}
			}
		}
	}
	return p.docs.Slice()
}
