package flow

import (
	"sync"
	"time"

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

// node

var NODE_CODES = []outputtype.Code{}

var NODE_PORT_CODES = []outputtype.Code{}

var STAT_CODES_LEN = len(NODE_CODES) + len(NODE_PORT_CODES)

// edge

var EDGE_CODES = []outputtype.Code{}

var TOR_EDGE_PORT_CODES = []outputtype.Code{}

var TOR_EDGE_PORT_CODES_LEN = len(TOR_EDGE_PORT_CODES)

var TOR_EDGE_CODES = []outputtype.Code{}

var STAT_EDGE_CODES_LEN = len(EDGE_CODES) + len(TOR_EDGE_CODES)

// policy node

var POLICY_NODE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLGID | outputtype.TAPType,
	outputtype.IndexToCode(0x01) | outputtype.ACLGID | outputtype.IP | outputtype.TAPType,
	outputtype.IndexToCode(0x02) | outputtype.ACLGID | outputtype.Protocol | outputtype.TAPType,
	outputtype.IndexToCode(0x03) | outputtype.ACLGID | outputtype.Protocol | outputtype.IP | outputtype.TAPType,
}

var POLICY_PORT_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x04) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Protocol | outputtype.ServerPort | outputtype.TAPType,
	outputtype.IndexToCode(0x05) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Protocol | outputtype.IP | outputtype.ServerPort | outputtype.TAPType,
}

var POLICY_NODE_PORT_CODES = []outputtype.Code{}

var POLICY_NODE_CODES_LEN = len(POLICY_NODE_CODES) + len(POLICY_PORT_CODES) + len(POLICY_NODE_PORT_CODES)

// policy edge

var POLICY_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x06) | outputtype.ACLGID | outputtype.IPPath | outputtype.TAPType,
	outputtype.IndexToCode(0x07) | outputtype.ACLGID | outputtype.Protocol | outputtype.IPPath | outputtype.TAPType,
}

var POLICY_EDGE_PORT_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x08) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Protocol | outputtype.IPPath | outputtype.ServerPort | outputtype.TAPType,
}

var POLICY_EDGE_CODES_LEN = len(POLICY_EDGE_CODES) + len(POLICY_EDGE_PORT_CODES)

// policy group

var POLICY_GROUP_NODE_CODES = []outputtype.Code{}

var POLICY_GROUP_NODE_PORT_CODES = []outputtype.Code{}

var POLICY_GROUP_NODE_CODES_LEN = len(POLICY_GROUP_NODE_CODES) + len(POLICY_GROUP_NODE_PORT_CODES)

// policy group edge

var POLICY_GROUP_EDGE_CODES = []outputtype.Code{}

var POLICY_GROUP_EDGE_PORT_CODES = []outputtype.Code{}

var POLICY_GROUP_EDGE_CODES_LEN = len(POLICY_GROUP_EDGE_CODES) + len(POLICY_GROUP_EDGE_PORT_CODES)

type FlowToFlowDocumentMapper struct {
	pool        *sync.Pool
	policyGroup []inputtype.AclAction

	docs         *utils.StructBuffer
	encoder      *codec.SimpleEncoder
	codes        []outputtype.Code
	rawSrcGroups []int32
	aclGroups    [2][]int32
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

func (p *FlowToFlowDocumentMapper) appendDoc(docMap map[string]bool, timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.FlowMeter, actionFlags uint32) {
	tag := &outputtype.Tag{
		Field: field,
		Code:  code,
	}

	if code.PossibleDuplicate() {
		id := tag.GetID(p.encoder)
		if _, exists := docMap[id]; exists {
			return
		}
		docMap[id] = true
	}

	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Tag.SetID(tag.GetID(p.encoder))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *FlowToFlowDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()

	if rawFlow.EthType != layers.EthernetTypeIPv4 {
		return p.docs.Slice()
	}
	flow := Flow(*rawFlow)

	actionFlags := rawFlow.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_FLOW_COUNTING | inputtype.ACTION_FLOW_COUNT_BROKERING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	statTemplates := GetTagTemplateByActionFlags(rawFlow.PolicyData, interestActions)
	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, interestActions, p.policyGroup)

	oneSideCodes := make([]outputtype.Code, 0, STAT_CODES_LEN)
	edgeCodes := make([]outputtype.Code, 0, STAT_EDGE_CODES_LEN)
	if actionFlags&inputtype.ACTION_FLOW_COUNTING != 0 {
		if statTemplates&inputtype.TEMPLATE_NODE != 0 {
			oneSideCodes = append(oneSideCodes, NODE_CODES...)
		}
		if statTemplates&inputtype.TEMPLATE_NODE_PORT != 0 && !flow.ServiceNotAlive() { // 含有端口号的，仅统计活跃端口
			oneSideCodes = append(oneSideCodes, NODE_PORT_CODES...)
		}
		if statTemplates&inputtype.TEMPLATE_EDGE != 0 {
			edgeCodes = append(edgeCodes, EDGE_CODES...)
			if TOR.IsPortInRange(flow.InPort) {
				edgeCodes = append(edgeCodes, TOR_EDGE_CODES...)
			}
		}
		if statTemplates&inputtype.TEMPLATE_EDGE_PORT != 0 && !flow.ServiceNotAlive() && TOR.IsPortInRange(flow.InPort) { // 含有端口号的，仅统计活跃端口
			edgeCodes = append(edgeCodes, TOR_EDGE_PORT_CODES...)
		}
	}

	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	hosts := [2]uint32{flow.FlowMetricsPeerSrc.Host, flow.FlowMetricsPeerDst.Host}
	isL2End := [2]bool{flow.FlowMetricsPeerSrc.IsL2End, flow.FlowMetricsPeerDst.IsL2End}
	isL3End := [2]bool{flow.FlowMetricsPeerSrc.IsL3End, flow.FlowMetricsPeerDst.IsL3End}
	docTimestamp := RoundToMinute(flow.StartTime)
	packets := [2]uint64{flow.FlowMetricsPeerSrc.PacketCount, flow.FlowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flow.FlowMetricsPeerSrc.ByteCount << 3, flow.FlowMetricsPeerDst.ByteCount << 3}

	p.rawSrcGroups = p.rawSrcGroups[:0]
	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.FlowMeter{ // FIXME: 待确认
			SumFlowCount:          1,
			SumNewFlowCount:       flow.NewFlowCount(),
			SumClosedFlowCount:    flow.ClosedFlowCount(),
			SumPacketTx:           packets[thisEnd],
			SumPacketRx:           packets[otherEnd],
			SumBitTx:              bits[thisEnd],
			SumBitRx:              bits[otherEnd],
			SumFlowDuration:       uint64(flow.Duration / time.Millisecond),             // ms
			SumClosedFlowDuration: uint64(flow.ClosedFlowDuration() / time.Millisecond), // ms
		}
		field := outputtype.Field{
			IP:           ips[thisEnd],
			TAPType:      TAPTypeFromInPort(flow.InPort),
			Protocol:     flow.Proto,
			ServerPort:   flow.PortDst,
			ACLDirection: outputtype.ACL_FORWARD, // 性能量化APP仅考虑ACL正向匹配

			IP1: ips[otherEnd],
		}

		// oneSideCodes
		for _, code := range oneSideCodes {
			if IsDupTraffic(flow.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
				continue
			}
			if IsWrongEndPoint(thisEnd, code) {
				continue
			}
			if code&outputtype.Host != 0 && hosts[thisEnd] == 0 {
				// 产品要求：统计服务器内所有虚拟接口流量之和
				continue
			}
			p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(inputtype.ACTION_FLOW_COUNTING))
		}

		// edgeCodes
		for _, code := range edgeCodes {
			if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧Tag
				continue
			}
			if IsWrongEndPoint(thisEnd, code) { // 双侧Tag
				continue
			}
			p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(inputtype.ACTION_FLOW_COUNTING))
		}

		// policy
		for _, policy := range p.policyGroup {
			field.ACLGID = uint16(policy.GetACLGID())

			// node
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_PORT != 0 && !flow.ServiceNotAlive() { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_PORT_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && !flow.ServiceNotAlive() { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				if code&outputtype.Host != 0 && hosts[thisEnd] == 0 {
					// 产品要求：统计服务器内所有虚拟接口流量之和
					continue
				}
				p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(policy.GetActionFlags()))
			}

			// edge
			codes = codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT != 0 && !flow.ServiceNotAlive() { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_EDGE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧Tag
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧Tag
					continue
				}
				p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(policy.GetActionFlags()))
			}

			flow.FillACLGroupID(policy, p.aclGroups[:])

			// group node & group node port
			codes = codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_GROUP_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && !flow.ServiceNotAlive() { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_GROUP_NODE_PORT_CODES...)
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
					p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(policy.GetActionFlags()))
				}
			}

			// group_edge
			srcGroups := p.aclGroups[thisEnd]
			codes = codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_GROUP_EDGE_CODES...)
			}
			// 白名单与其他应用不会使用同一个acl_gid，所以这里是正确的
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT != 0 && !flow.ServiceNotAlive() {
				codes = append(codes, POLICY_GROUP_EDGE_PORT_CODES...)
			} else if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT_ALL != 0 &&
				TOR.IsPortInRange(flow.InPort) && flow.IsInterestWhitelistServerPort() {
				codes = append(codes, POLICY_GROUP_EDGE_PORT_CODES...) // 白名单：虚拟网络、所有端口，即使端口号不活跃也需要记录
				// 白名单使用未经acl过滤的源资源组
				if len(p.rawSrcGroups) == 0 {
					for _, v := range flow.GroupIDs0 {
						p.rawSrcGroups = append(p.rawSrcGroups, int32(inputtype.FormatGroupId(v)))
					}
					if len(p.rawSrcGroups) == 0 {
						p.rawSrcGroups = append(p.rawSrcGroups, -1)
					}
				}
				srcGroups = p.rawSrcGroups
			}

			for _, code := range codes {
				for _, gidSrc := range srcGroups {
					field.GroupID = int16(gidSrc)
					for _, gidDst := range p.aclGroups[otherEnd] {
						field.GroupID1 = int16(gidDst)
						if IsDupTraffic(flow.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧Tag
							continue
						}
						if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) { // 双侧Tag
							continue
						}
						p.appendDoc(docMap, docTimestamp, &field, code, &meter, uint32(policy.GetActionFlags()))
					}
				}
			}
		}
	}
	return p.docs.Slice()
}
