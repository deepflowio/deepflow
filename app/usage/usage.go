package usage

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
	"net"

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

	if !(rawFlow.EthType == layers.EthernetTypeIPv4 || rawFlow.EthType == layers.EthernetTypeIPv6) {
		return p.docs.Slice()
	}

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_PACKET_COUNTING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	p.policyGroup = FillPolicyTagTemplate(&rawFlow.PolicyData, interestActions, p.policyGroup)

	flow := Flow(*rawFlow)
	flowMetricsPeerSrc := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]

	l3EpcIDs := [2]int32{flowMetricsPeerSrc.L3EpcID, flowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	ip6s := [2]net.IP{flow.IP6Src, flow.IP6Dst}
	// 虚拟网络流量用is_l2_end和is_l3_end去重
	// 接入网络流量只有一份，不去重
	statsEndpoint := [2]bool{true, true}
	if TOR.IsPortInRange(flow.InPort) {
		statsEndpoint[0] = flowMetricsPeerSrc.IsL2End && flowMetricsPeerSrc.IsL3End
		statsEndpoint[1] = flowMetricsPeerDst.IsL2End && flowMetricsPeerDst.IsL3End
	}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	docTimestamp := RoundToSecond(flow.PacketStatTime)
	packets := [2]uint64{flowMetricsPeerSrc.TickPacketCount, flowMetricsPeerDst.TickPacketCount}
	bits := [2]uint64{flowMetricsPeerSrc.TickByteCount << 3, flowMetricsPeerDst.TickByteCount << 3}

	isActiveHost := [2]bool{flowMetricsPeerSrc.IsActiveHost, flowMetricsPeerDst.IsActiveHost}
	for i := range ips {
		if !isActiveHost[i] || IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
			ip6s[i] = net.IPv6zero
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		if !statsEndpoint[thisEnd] {
			continue
		}
		otherEnd := GetOppositeEndpoint(thisEnd)

		meter := &p.meters[thisEnd]
		meter.SumPacketTx = packets[thisEnd]
		meter.SumPacketRx = packets[otherEnd]
		meter.SumBitTx = bits[thisEnd]
		meter.SumBitRx = bits[otherEnd]

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
		field.Protocol = flow.Proto
		field.ServerPort = flow.PortDst
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
				if thisEnd == ONE && code.IsSymmetric() {
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
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}
		}
	}
	return p.docs.Slice()
}
