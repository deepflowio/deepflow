package flow

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

var log = logging.MustGetLogger("flow")

const (
	CODES_LEN  = 64
	GROUPS_LEN = 16
)

type FlowToFlowDocumentMapper struct {
	pool        *sync.Pool
	policyGroup []inputtype.AclAction

	docs         *utils.StructBuffer
	encoder      *codec.SimpleEncoder
	codes        []outputtype.Code
	rawSrcGroups []int32
	aclGroups    [2][]int32

	fields [2]outputtype.Field
	meters [2]outputtype.FlowMeter
}

func (p *FlowToFlowDocumentMapper) GetName() string {
	return "FlowToFlowDocumentMapper"
}

func NewProcessor() app.FlowProcessor {
	return &FlowToFlowDocumentMapper{}
}

func (p *FlowToFlowDocumentMapper) Prepare() {
	p.policyGroup = make([]inputtype.AclAction, 0)
	p.docs = NewMeterSharedDocBuffer()
	p.encoder = &codec.SimpleEncoder{}
	p.codes = make([]outputtype.Code, 0, CODES_LEN)
	p.rawSrcGroups = make([]int32, 0, GROUPS_LEN)
	p.aclGroups = [2][]int32{make([]int32, 0, GROUPS_LEN), make([]int32, 0, GROUPS_LEN)}
}

func (p *FlowToFlowDocumentMapper) appendDoc(timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.FlowMeter, actionFlags uint32) {
	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.Flags = app.DocumentFlag(actionFlags)
}

func (p *FlowToFlowDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	return p.docs.Slice() // v5.5.5弃用

	p.docs.Reset()

	if !(rawFlow.EthType == layers.EthernetTypeIPv4 || rawFlow.EthType == layers.EthernetTypeIPv6) {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_FLOW_COUNTING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	statTemplates := GetTagTemplateByActionFlags(&rawFlow.PolicyData, interestActions)
	p.policyGroup = FillPolicyTagTemplate(&rawFlow.PolicyData, interestActions, p.policyGroup)

	oneSideCodes := make([]outputtype.Code, 0, NODE_CODES_LEN)
	edgeCodes := make([]outputtype.Code, 0, EDGE_CODES_LEN)
	if statTemplates&inputtype.TEMPLATE_NODE != 0 {
		oneSideCodes = append(oneSideCodes, NODE_CODES...)
	}
	if statTemplates&inputtype.TEMPLATE_NODE_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
		oneSideCodes = append(oneSideCodes, NODE_PORT_CODES...)
	}
	if statTemplates&inputtype.TEMPLATE_EDGE != 0 {
		edgeCodes = append(edgeCodes, EDGE_CODES...)
		if TOR.IsPortInRange(flow.InPort) {
			edgeCodes = append(edgeCodes, TOR_EDGE_CODES...)
		}
	}
	if statTemplates&inputtype.TEMPLATE_EDGE_PORT != 0 && flow.IsActiveService && TOR.IsPortInRange(flow.InPort) { // 含有端口号的，仅统计活跃端口
		edgeCodes = append(edgeCodes, TOR_EDGE_PORT_CODES...)
	}

	flowMetricsPeerSrc := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &flow.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]
	l3EpcIDs := [2]int32{flowMetricsPeerSrc.L3EpcID, flowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	ip6s := [2]net.IP{flow.IP6Src, flow.IP6Dst}
	hosts := [2]uint32{flowMetricsPeerSrc.Host, flowMetricsPeerDst.Host}
	// 虚拟网络流量用is_l2_end和is_l3_end去重
	// 接入网络流量只有一份，不去重
	statsEndpoint := [2]bool{true, true}
	if TOR.IsPortInRange(flow.InPort) {
		statsEndpoint[0] = flowMetricsPeerSrc.IsL2End && flowMetricsPeerSrc.IsL3End
		statsEndpoint[1] = flowMetricsPeerDst.IsL2End && flowMetricsPeerDst.IsL3End
	}
	docTimestamp := RoundToMinute(flow.StartTime)
	packets := [2]uint64{flowMetricsPeerSrc.PacketCount, flowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flowMetricsPeerSrc.ByteCount << 3, flowMetricsPeerDst.ByteCount << 3}

	p.rawSrcGroups = p.rawSrcGroups[:0]
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
		meter.SumFlowCount = 1
		meter.SumNewFlowCount = flow.NewFlowCount()
		meter.SumClosedFlowCount = flow.ClosedFlowCount()
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

		// oneSideCodes
		for _, code := range oneSideCodes {
			if code&outputtype.HostID != 0 && hosts[thisEnd] == 0 {
				// 产品要求：统计服务器内所有虚拟接口流量之和
				continue
			}
			if thisEnd == ONE && code.IsSymmetric() {
				continue
			}
			p.appendDoc(docTimestamp, field, code, meter, uint32(inputtype.ACTION_FLOW_COUNTING))
		}

		// edgeCodes
		for _, code := range edgeCodes {
			p.appendDoc(docTimestamp, field, code, meter, uint32(inputtype.ACTION_FLOW_COUNTING))
		}

		// policy
		for _, policy := range p.policyGroup {
			field.ACLGID = uint16(policy.GetACLGID())

			// node
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_PORT_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && flow.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			for _, code := range codes {
				if code&outputtype.HostID != 0 && hosts[thisEnd] == 0 {
					// 产品要求：统计服务器内所有虚拟接口流量之和
					continue
				}
				if thisEnd == ONE && code.IsSymmetric() {
					continue
				}
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}

			// edge
			codes = codes[:0]
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
