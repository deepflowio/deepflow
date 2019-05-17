package geo

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/geo"
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

var log = logging.MustGetLogger("geo")

const (
	GROUPS_LEN = 16
)

var CHN_ID = uint8(0)

func init() {
	for id, name := range COUNTRY_NAMES {
		if name == "CHN" {
			CHN_ID = uint8(id)
			break
		}
	}
	if DecodeCountry(CHN_ID) != "CHN" {
		panic("国家代码不正确")
	}
}

// 注意：仅统计TCP流
// 注意：此应用中请不要加入ServerPort或XXPath的Tag组合

var POLICY_CHN_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x00) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.ISPCode | outputtype.TAPType,
	outputtype.IndexToCode(0x01) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.Region | outputtype.TAPType,
	outputtype.IndexToCode(0x02) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.ISPCode | outputtype.TAPType,
	outputtype.IndexToCode(0x03) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.Region | outputtype.TAPType,
	outputtype.IndexToCode(0x04) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.Country | outputtype.TAPType,
	outputtype.IndexToCode(0x05) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IP | outputtype.Country | outputtype.TAPType,
}

var POLICY_NON_CHN_CODES = []outputtype.Code{ // 注意：就是POLICY_CHN_CODES中包含Country的部分
	// v5.5.3：产品没有世界地图需求
}

var POLICY_CHN_EDGE_CODES = []outputtype.Code{
	outputtype.IndexToCode(0x06) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.ISPCode | outputtype.TAPType,
	outputtype.IndexToCode(0x07) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.Region | outputtype.TAPType,
	outputtype.IndexToCode(0x08) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.Direction | outputtype.IPPath | outputtype.Country | outputtype.TAPType,
}

var POLICY_NON_CHN_EDGE_CODES = []outputtype.Code{ // 注意：就是POLICY_CHN_EDGE_CODES中包含Country的部分
	// v5.5.3：产品没有世界地图需求
}

var POLICY_CHN_GROUP_NODE_CODES = []outputtype.Code{}

var POLICY_NON_CHN_GROUP_NODE_CODES = []outputtype.Code{}

type FlowToGeoDocumentMapper struct {
	geoFile string

	policyGroup []inputtype.AclAction

	docs      *utils.StructBuffer
	encoder   *codec.SimpleEncoder
	aclGroups [2][]int32
}

func (p *FlowToGeoDocumentMapper) GetName() string {
	return "FlowToGeoDocumentMapper"
}

func NewProcessor(geoFile string) app.FlowProcessor {
	return &FlowToGeoDocumentMapper{geoFile: geoFile}
}

func (p *FlowToGeoDocumentMapper) Prepare() {
	p.docs = NewMeterSharedDocBuffer()
	p.policyGroup = make([]inputtype.AclAction, 0)
	p.encoder = &codec.SimpleEncoder{}
	p.aclGroups = [2][]int32{make([]int32, 0, GROUPS_LEN), make([]int32, 0, GROUPS_LEN)}
}

func (p *FlowToGeoDocumentMapper) Process(rawFlow *inputtype.TaggedFlow, variedTag bool) []interface{} {
	p.docs.Reset()

	if rawFlow.GeoEnd != uint8(ZERO) { // 产品需求：永远仅统计云外、客户端的地理位置信息
		return p.docs.Slice()
	}
	if rawFlow.Proto != layers.IPProtocolTCP {
		return p.docs.Slice()
	}
	actionFlags := rawFlow.PolicyData.ActionFlags
	if actionFlags&inputtype.ACTION_GEO_POSITIONING == 0 {
		return p.docs.Slice()
	}

	p.policyGroup = FillPolicyTagTemplate(rawFlow.PolicyData, inputtype.ACTION_GEO_POSITIONING, p.policyGroup)

	flow := Flow(*rawFlow)
	l3EpcIDs := [2]int32{flow.FlowMetricsPeerSrc.L3EpcID, flow.FlowMetricsPeerDst.L3EpcID}
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2End := [2]bool{flow.FlowMetricsPeerSrc.IsL2End, flow.FlowMetricsPeerDst.IsL2End}
	isL3End := [2]bool{flow.FlowMetricsPeerSrc.IsL3End, flow.FlowMetricsPeerDst.IsL3End}
	packets := [2]uint64{flow.FlowMetricsPeerSrc.PacketCount, flow.FlowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flow.FlowMetricsPeerSrc.ByteCount << 3, flow.FlowMetricsPeerDst.ByteCount << 3}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	docTimestamp := RoundToMinute(flow.StartTime)

	for i := range ips {
		if IsOuterPublicIp(l3EpcIDs[i]) {
			ips[i] = 0
		}
	}

	docMap := make(map[string]bool)

	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		meter := outputtype.GeoMeter{ // FIXME: 确认字段
			SumClosedFlowCount:    flow.ClosedFlowCount(),
			SumAbnormalFlowCount:  flow.AbnormalFlowCount(),
			SumClosedFlowDuration: uint64(flow.ClosedFlowDuration() / time.Millisecond), // ms
			SumPacketTx:           packets[thisEnd],
			SumPacketRx:           packets[otherEnd],
			SumBitTx:              bits[thisEnd],
			SumBitRx:              bits[otherEnd],

			SumRTTSynClient:     flow.ClosedRTTSynClient(),
			SumRTTSynClientFlow: flow.RTTSynClientFlow(),
		}

		field := outputtype.Field{
			IP:           ips[thisEnd],
			TAPType:      TAPTypeFromInPort(flow.InPort),
			Direction:    directions[thisEnd],
			ACLDirection: outputtype.ACL_FORWARD, // 含ACLDirection字段时仅考虑ACL正向匹配
			Country:      flow.Country,
			Region:       flow.Region,
			ISP:          flow.ISP,
		}
		var codes []outputtype.Code

		// policy
		for _, policy := range p.policyGroup {
			field.ACLGID = uint16(policy.GetACLGID())

			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_NODE != 0 && thisEnd == ONE {
				// 产品需求：永远仅统计云外、客户端的地理位置信息，即单侧统计量永远基于服务端视角
				if flow.Country == CHN_ID {
					codes = POLICY_CHN_CODES[:]
				} else {
					codes = POLICY_NON_CHN_CODES[:]
				}
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
			}

			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 && thisEnd == ZERO {
				// 产品需求：永远仅统计云外、客户端的地理位置信息，即双侧统计量永远基于客户端视角
				if flow.Country == CHN_ID {
					codes = POLICY_CHN_EDGE_CODES[:]
				} else {
					codes = POLICY_NON_CHN_EDGE_CODES[:]
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
			}

			flow.FillACLGroupID(policy, p.aclGroups[:])

			// group
			if flow.Country == CHN_ID {
				codes = POLICY_CHN_GROUP_NODE_CODES[:]
			} else {
				codes = POLICY_NON_CHN_GROUP_NODE_CODES[:]
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
		}

	}
	return p.docs.Slice()
}
