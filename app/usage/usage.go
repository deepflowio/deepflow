package usage

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

// node

var NODE_CODES = []outputtype.Code{}

var STAT_CODES_LEN = len(NODE_CODES)

// policy node

var POLICY_NODE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLDirection | outputtype.ACLGID | outputtype.Direction | outputtype.IP | outputtype.TAPType,
}

var POLICY_NODE_PORT_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x01) | outputtype.ACLDirection | outputtype.ACLGID | outputtype.Direction | outputtype.IP | outputtype.Protocol | outputtype.ServerPort | outputtype.TAPType,
}

var POLICY_NODE_CODES_LEN = len(POLICY_NODE_CODES) + len(POLICY_NODE_PORT_CODES)

// policy edge

var POLICY_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x02) | outputtype.ACLDirection | outputtype.ACLGID | outputtype.Direction | outputtype.IPPath | outputtype.TAPType,
}

var POLICY_EDGE_PORT_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x03) | outputtype.ACLDirection | outputtype.ACLGID | outputtype.Direction | outputtype.IPPath | outputtype.Protocol | outputtype.ServerPort | outputtype.TAPType,
}

var POLICY_EDGE_CODES_LEN = len(POLICY_EDGE_CODES) + len(POLICY_EDGE_PORT_CODES)

type MeteringToUsageDocumentMapper struct {
	docs        *utils.StructBuffer
	policyGroup []inputtype.AclAction

	encoder *codec.SimpleEncoder
	codes   []outputtype.Code

	fields [2]outputtype.Field
	// 预先计算好包长为0~65535的包、双方向上所有可能的meter
	meters [1 << 16][2]*outputtype.UsageMeter
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

	for i := range p.meters {
		p.meters[i][0] = &outputtype.UsageMeter{
			SumPacketTx: 1,
			SumPacketRx: 0,
			SumBitTx:    uint64(i << 3),
			SumBitRx:    0,
		}
		p.meters[i][1] = &outputtype.UsageMeter{
			SumPacketTx: 0,
			SumPacketRx: 1,
			SumBitTx:    0,
			SumBitRx:    uint64(i << 3),
		}
	}
}

func (p *MeteringToUsageDocumentMapper) appendDoc(docMap map[string]bool, timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.UsageMeter, actionFlags uint32) {
	if code.PossibleDuplicate() {
		tag := &outputtype.Tag{
			Field: field,
			Code:  code,
		}
		id := tag.GetID(p.encoder)
		if _, exists := docMap[id]; exists {
			return
		}
		docMap[id] = true
	}

	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *MeteringToUsageDocumentMapper) Process(metaPacket *inputtype.MetaPacket, variedTag bool) []interface{} {
	p.docs.Reset()

	actionFlags := metaPacket.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_PACKET_COUNTING | inputtype.ACTION_PACKET_COUNT_BROKERING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	p.policyGroup = FillPolicyTagTemplate(metaPacket.PolicyData, interestActions, p.policyGroup)

	l3EpcIDs := [2]int32{metaPacket.EndpointData.SrcInfo.L3EpcId, metaPacket.EndpointData.DstInfo.L3EpcId}
	ips := [2]uint32{metaPacket.IpSrc, metaPacket.IpDst}
	isL2End := [2]bool{metaPacket.EndpointData.SrcInfo.L2End, metaPacket.EndpointData.DstInfo.L2End}
	isL3End := [2]bool{metaPacket.EndpointData.SrcInfo.L3End, metaPacket.EndpointData.DstInfo.L3End}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	serverPort := metaPacket.PortDst
	if metaPacket.Direction == inputtype.SERVER_TO_CLIENT {
		l3EpcIDs[0], l3EpcIDs[1] = l3EpcIDs[1], l3EpcIDs[0]
		ips[0], ips[1] = ips[1], ips[0]
		isL2End[0], isL2End[1] = isL2End[1], isL2End[0]
		isL3End[0], isL3End[1] = isL3End[1], isL3End[0]
		directions[0], directions[1] = directions[1], directions[0]
		serverPort = metaPacket.PortSrc
	}
	docTimestamp := RoundToSecond(metaPacket.Timestamp)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)

		meter := p.meters[metaPacket.PacketLen][thisEnd]
		field := &p.fields[thisEnd]
		field.IP = ips[thisEnd]
		field.IP1 = ips[otherEnd]
		field.TAPType = TAPTypeFromInPort(metaPacket.InPort)
		field.Protocol = metaPacket.Protocol
		field.ServerPort = serverPort
		field.ACLDirection = outputtype.ACL_FORWARD // 含ACLDirection字段时仅考虑ACL正向匹配
		field.Direction = directions[thisEnd]

		for _, policy := range p.policyGroup {
			field.ACLGID = uint16(policy.GetACLGID())
			var policyDirections inputtype.DirectionType
			if metaPacket.Direction == inputtype.CLIENT_TO_SERVER {
				policyDirections = policy.GetDirections()
			} else {
				policyDirections = policy.ReverseDirection().GetDirections()
			}

			// node
			codes := p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 {
				codes = append(codes, POLICY_NODE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && metaPacket.Protocol == layers.IPProtocolTCP {
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(metaPacket.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policyDirections, code) {
					continue
				}
				p.appendDoc(docMap, docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}

			// edge
			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT != 0 && metaPacket.Protocol == layers.IPProtocolTCP {
				codes = append(codes, POLICY_EDGE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(metaPacket.InPort, l3EpcIDs[otherEnd], isL2End[otherEnd], isL3End[otherEnd], code) { // 双侧tag用otherEnd判断
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policyDirections, code) {
					continue
				}
				p.appendDoc(docMap, docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}
		}
	}
	return p.docs.Slice()
}
