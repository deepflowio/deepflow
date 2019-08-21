package flowtype

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
	logging "github.com/op/go-logging"
)

// 注意：仅统计TCP流

var log = logging.MustGetLogger("flowtype")

const (
	CODES_LEN     = 64
	GROUPS_LEN    = 16
	MAX_FLOW_TYPE = inputtype.CloseTypeClientHalfClose + 1
)

// node

var NODE_CODES = []outputtype.Code{}

// policy node

var POLICY_NODE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.TAPType,
}

var POLICY_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x01) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.TAPType,
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

	fields [2]outputtype.Field
	meters [MAX_FLOW_TYPE]outputtype.TypeMeter
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

	for flowType := inputtype.CloseType(0); flowType <= MAX_FLOW_TYPE; flowType++ {
		switch flowType {
		case inputtype.CloseTypeTCPServerRst:
			p.meters[flowType].SumCountTServerRst = 1
		case inputtype.CloseTypeTCPClientRst:
			p.meters[flowType].SumCountTClientRst = 1
		case inputtype.CloseTypeServerHalfOpen:
			p.meters[flowType].SumCountTServerHalfOpen = 1
		case inputtype.CloseTypeClientHalfOpen:
			p.meters[flowType].SumCountTClientHalfOpen = 1
		case inputtype.CloseTypeServerHalfClose:
			p.meters[flowType].SumCountTServerHalfClose = 1
		case inputtype.CloseTypeClientHalfClose:
			p.meters[flowType].SumCountTClientHalfClose = 1
		}
	}
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
	if flow.CloseType >= MAX_FLOW_TYPE {
		return p.docs.Slice()
	}

	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActionFlags)
	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, interestActionFlags, p.policyGroup)

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2L3End := [2]bool{
		flow.FlowMetricsPeerSrc.IsL2End && flow.FlowMetricsPeerSrc.IsL3End,
		flow.FlowMetricsPeerDst.IsL2End && flow.FlowMetricsPeerDst.IsL3End,
	}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	docTimestamp := RoundToMinute(flow.StartTime)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)

		meter := &p.meters[flow.CloseType]

		field := &p.fields[thisEnd]
		field.IP = ips[thisEnd]
		field.TAPType = TAPTypeFromInPort(flow.InPort)
		field.Direction = directions[thisEnd]
		field.ACLDirection = outputtype.ACL_FORWARD // 含ACLDirection字段时仅考虑ACL正向匹配
		field.IP1 = ips[otherEnd]

		// node
		if statTemplates&inputtype.TEMPLATE_NODE != 0 {
			for _, code := range NODE_CODES {
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPoint(thisEnd, code) {
					continue
				}
				doc := p.docs.Get().(*app.Document)
				doc.Timestamp = docTimestamp
				field.FillTag(code, doc.Tag.(*outputtype.Tag))
				doc.Meter = meter
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
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				doc := p.docs.Get().(*app.Document)
				doc.Timestamp = docTimestamp
				field.FillTag(code, doc.Tag.(*outputtype.Tag))
				doc.Meter = meter
			}

			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧tag
					continue
				}
				doc := p.docs.Get().(*app.Document)
				doc.Timestamp = docTimestamp
				field.FillTag(code, doc.Tag.(*outputtype.Tag))
				doc.Meter = meter
			}
		}
	}
	return p.docs.Slice()
}
