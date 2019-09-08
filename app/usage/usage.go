package usage

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
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
	. "gitlab.x.lan/yunshan/droplet/app/common/policy"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("usage")

const (
	CODES_LEN = 64
)

type MeteringToUsageDocumentMapper struct {
	docs        *utils.StructBuffer
	policyGroup []inputtype.AclAction

	encoder *codec.SimpleEncoder
	codes   []outputtype.Code

	fields [2]outputtype.Field
	meters [2]outputtype.UsageMeter
}

func (p *MeteringToUsageDocumentMapper) GetName() string {
	return "MeteringToUsageDocumentMapper"
}

func NewProcessor() app.MeteringProcessor {
	return &MeteringToUsageDocumentMapper{}
}

func (p *MeteringToUsageDocumentMapper) Prepare() {
	p.docs = NewMeterSharedDocBuffer()
	p.policyGroup = make([]inputtype.AclAction, 0)
	p.encoder = &codec.SimpleEncoder{}
	p.codes = make([]outputtype.Code, 0, CODES_LEN)
}

func (p *MeteringToUsageDocumentMapper) appendDoc(timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.UsageMeter, actionFlags uint32) {
	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *MeteringToUsageDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()

	if rawFlow.EthType != layers.EthernetTypeIPv4 {
		return p.docs.Slice()
	}

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_PACKET_COUNTING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, interestActions, p.policyGroup)

	flow := Flow(*rawFlow)
	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2L3End := [2]bool{
		flow.FlowMetricsPeerSrc.IsL2End && flow.FlowMetricsPeerSrc.IsL3End,
		flow.FlowMetricsPeerDst.IsL2End && flow.FlowMetricsPeerDst.IsL3End,
	}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	docTimestamp := RoundToSecond(flow.PacketStatTime)
	packets := [2]uint64{flow.FlowMetricsPeerSrc.TickPacketCount, flow.FlowMetricsPeerDst.TickPacketCount}
	bits := [2]uint64{flow.FlowMetricsPeerSrc.TickByteCount << 3, flow.FlowMetricsPeerDst.TickByteCount << 3}

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)

		meter := &p.meters[thisEnd]
		meter.SumPacketTx = packets[thisEnd]
		meter.SumPacketRx = packets[otherEnd]
		meter.SumBitTx = bits[thisEnd]
		meter.SumBitRx = bits[otherEnd]

		field := &p.fields[thisEnd]
		field.IP = ips[thisEnd]
		field.IP1 = ips[otherEnd]
		field.TAPType = TAPTypeFromInPort(flow.InPort)
		field.Protocol = flow.Proto
		field.ServerPort = flow.PortDst
		field.ACLDirection = outputtype.ACL_FORWARD // 含ACLDirection字段时仅考虑ACL正向匹配
		field.Direction = directions[thisEnd]

		for _, policy := range p.policyGroup {
			field.ACLGID = uint16(policy.GetACLGID())

			// node
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}

			// edge
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
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}
		}
	}
	return p.docs.Slice()
}
