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

func (p *MeteringToUsageDocumentMapper) appendDoc(timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.UsageMeter, actionFlags uint32) {
	doc := p.docs.Get().(*app.Document)
	field.FillTag(code, doc.Tag.(*outputtype.Tag))
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *MeteringToUsageDocumentMapper) Process(metaPacket *inputtype.MetaPacket, variedTag bool) []interface{} {
	p.docs.Reset()

	if metaPacket.EthType != layers.EthernetTypeIPv4 {
		return p.docs.Slice()
	}

	actionFlags := metaPacket.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_PACKET_COUNTING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	p.policyGroup = FillPolicyTagTemplate(metaPacket.PolicyData, interestActions, p.policyGroup)

	l3EpcIDs := [2]int32{metaPacket.EndpointData.SrcInfo.L3EpcId, metaPacket.EndpointData.DstInfo.L3EpcId}
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{metaPacket.IpSrc, metaPacket.IpDst}
	isL2L3End := [2]bool{
		metaPacket.EndpointData.SrcInfo.L2End && metaPacket.EndpointData.SrcInfo.L3End,
		metaPacket.EndpointData.DstInfo.L2End && metaPacket.EndpointData.DstInfo.L3End,
	}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	serverPort := metaPacket.PortDst
	if metaPacket.Direction == inputtype.SERVER_TO_CLIENT {
		l3EpcIDs[0], l3EpcIDs[1] = l3EpcIDs[1], l3EpcIDs[0]
		ips[0], ips[1] = ips[1], ips[0]
		isL2L3End[0], isL2L3End[1] = isL2L3End[1], isL2L3End[0]
		serverPort = metaPacket.PortSrc
	}
	docTimestamp := RoundToSecond(metaPacket.Timestamp)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	var meter *outputtype.UsageMeter
	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)

		if metaPacket.Direction == inputtype.SERVER_TO_CLIENT {
			meter = p.meters[metaPacket.PacketLen][otherEnd]
		} else {
			meter = p.meters[metaPacket.PacketLen][thisEnd]
		}
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
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE_PORT != 0 && metaPacket.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_NODE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(metaPacket.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policyDirections, code) {
					continue
				}
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}

			// edge
			codes = p.codes[:0]
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 {
				codes = append(codes, POLICY_EDGE_CODES...)
			}
			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE_PORT != 0 && metaPacket.IsActiveService { // 含有端口号的，仅统计活跃端口
				codes = append(codes, POLICY_EDGE_PORT_CODES...)
			}
			for _, code := range codes {
				if IsDupTraffic(metaPacket.InPort, isL2L3End[thisEnd], isL2L3End[otherEnd], isNorthSouthTraffic, code) {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policyDirections, code) {
					continue
				}
				p.appendDoc(docTimestamp, field, code, meter, uint32(policy.GetActionFlags()))
			}
		}
	}
	return p.docs.Slice()
}
