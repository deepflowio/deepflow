package usage

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
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

// 注意：此应用中请不要加入ServerPort的Tag组合，如有需要加入flow中
// 注意：包统计应用中请不要加入双侧Tag，无法分辨方向

// node

var NODE_CODES = []outputtype.Code{}

var STAT_CODES_LEN = len(NODE_CODES)

// policy node

var POLICY_NODE_CODES = []outputtype.Code{}

var POLICY_NODE_CODES_LEN = len(POLICY_NODE_CODES)

type MeteringToUsageDocumentMapper struct {
	docs        *utils.StructBuffer
	policyGroup []inputtype.AclAction

	// 预先计算好包长为0~65535的包、双方向上所有可能的meter
	meters [1 << 16][2]*outputtype.UsageMeter

	// usage的tag少，使用slice而非map判断tag的重复。
	//   - 一方面查找更快: https://www.darkcoding.net/software/go-slice-search-vs-map-lookup/
	//   - 另一方面没有频繁的对象创建和销毁
	docMap []uint64
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

	p.docMap = make([]uint64, 0, 16) // 预先初始化一块内存
}

func (p *MeteringToUsageDocumentMapper) fastFillTag(tag *outputtype.Tag, field *outputtype.Field, code outputtype.Code) {
	if code&^(outputtype.CodeIndices|outputtype.TAPType|outputtype.L3EpcID|outputtype.IP|outputtype.ACLGID) != 0 {
		panic("添加的Tag Field没有加入fastFillTag中")
	}

	// MeterSharedDocBuffer的Tag.Field一定非空
	f := tag.Field
	f.IP = field.IP
	f.L3EpcID = field.L3EpcID
	f.ACLGID = field.ACLGID
	f.TAPType = field.TAPType
	tag.Code = code
	tag.SetID("")
}

func (p *MeteringToUsageDocumentMapper) appendDoc(timestamp uint32, field *outputtype.Field, code outputtype.Code, meter *outputtype.UsageMeter, actionFlags uint32) {
	if code.PossibleDuplicate() {
		tag := &outputtype.Tag{
			Field: field,
			Code:  code,
		}
		fastID := tag.GetFastID()
		for _, v := range p.docMap {
			if v == fastID {
				return
			}
		}
		p.docMap = append(p.docMap, fastID)
	}

	doc := p.docs.Get().(*app.Document)
	p.fastFillTag(doc.Tag.(*outputtype.Tag), field, code)
	doc.Meter = meter
	doc.Timestamp = timestamp
	doc.ActionFlags = actionFlags
}

func (p *MeteringToUsageDocumentMapper) Process(metaPacket *inputtype.MetaPacket, variedTag bool) []interface{} {
	return p.docs.Slice() // v5.5.3弃用

	p.docs.Reset()
	p.docMap = p.docMap[:0]

	actionFlags := metaPacket.PolicyData.ActionFlags
	interestActions := inputtype.ACTION_PACKET_COUNTING | inputtype.ACTION_PACKET_COUNT_BROKERING
	if actionFlags&interestActions == 0 {
		return p.docs.Slice()
	}

	statTemplates := GetTagTemplateByActionFlags(metaPacket.PolicyData, interestActions)
	p.policyGroup = FillPolicyTagTemplate(metaPacket.PolicyData, interestActions, p.policyGroup)

	l3EpcIDs := [2]int32{metaPacket.EndpointData.SrcInfo.L3EpcId, metaPacket.EndpointData.DstInfo.L3EpcId}
	ips := [2]uint32{metaPacket.IpSrc, metaPacket.IpDst}
	isL2End := [2]bool{metaPacket.EndpointData.SrcInfo.L2End, metaPacket.EndpointData.DstInfo.L2End}
	isL3End := [2]bool{metaPacket.EndpointData.SrcInfo.L3End, metaPacket.EndpointData.DstInfo.L3End}
	docTimestamp := RoundToSecond(metaPacket.Timestamp)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		meter := p.meters[metaPacket.PacketLen][thisEnd]
		field := outputtype.Field{
			IP:      ips[thisEnd],
			TAPType: TAPTypeFromInPort(metaPacket.InPort),
			L3EpcID: int16(l3EpcIDs[thisEnd]),
		}

		// node
		if actionFlags&inputtype.ACTION_PACKET_COUNTING != 0 && statTemplates&inputtype.TEMPLATE_NODE != 0 {
			for _, code := range NODE_CODES {
				if IsDupTraffic(metaPacket.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
					continue
				}
				if IsWrongEndPoint(thisEnd, code) {
					continue
				}
				p.appendDoc(docTimestamp, &field, code, meter, uint32(inputtype.ACTION_PACKET_COUNTING))
			}
		}

		// policy: node
		for _, code := range POLICY_NODE_CODES {
			if IsDupTraffic(metaPacket.InPort, l3EpcIDs[thisEnd], isL2End[thisEnd], isL3End[thisEnd], code) {
				continue
			}

			for _, policy := range p.policyGroup {
				if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE == 0 {
					continue
				}
				if IsWrongEndPointWithACL(thisEnd, policy.GetDirections(), code) {
					continue
				}
				field.ACLGID = uint16(policy.GetACLGID())

				p.appendDoc(docTimestamp, &field, code, meter, uint32(policy.GetActionFlags()))
			}
		}
	}
	return p.docs.Slice()
}
