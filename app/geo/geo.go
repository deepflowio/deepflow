package geo

//go:generate tmpl -data=@codes.tmpldata -o codes.go ../common/gen/codes.go.tmpl

import (
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

type FlowToGeoDocumentMapper struct {
	geoFile string

	policyGroup []inputtype.AclAction

	docs      *utils.StructBuffer
	encoder   *codec.SimpleEncoder
	aclGroups [2][]int32

	fields [2]outputtype.Field
	meters [2]outputtype.GeoMeter
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
	isNorthSouthTraffic := IsNorthSourceTraffic(l3EpcIDs[0], l3EpcIDs[1])
	ips := [2]uint32{flow.IPSrc, flow.IPDst}
	isL2L3End := [2]bool{
		flow.FlowMetricsPeerSrc.IsL2End && flow.FlowMetricsPeerSrc.IsL3End,
		flow.FlowMetricsPeerDst.IsL2End && flow.FlowMetricsPeerDst.IsL3End,
	}
	packets := [2]uint64{flow.FlowMetricsPeerSrc.PacketCount, flow.FlowMetricsPeerDst.PacketCount}
	bits := [2]uint64{flow.FlowMetricsPeerSrc.ByteCount << 3, flow.FlowMetricsPeerDst.ByteCount << 3}
	directions := [2]outputtype.DirectionEnum{outputtype.ClientToServer, outputtype.ServerToClient}
	docTimestamp := RoundToMinute(flow.StartTime)

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
		meter.SumRTTSynClient = flow.ClosedRTTSynClient()
		meter.SumRTTSynClientFlow = flow.RTTSynClientFlow()

		field := &p.fields[thisEnd]
		field.IP = ips[thisEnd]
		field.TAPType = TAPTypeFromInPort(flow.InPort)
		field.Direction = directions[thisEnd]
		field.ACLDirection = outputtype.ACL_FORWARD // 含ACLDirection字段时仅考虑ACL正向匹配
		field.IP1 = ips[otherEnd]
		field.Country = flow.Country
		field.Region = flow.Region
		field.ISP = flow.ISP

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
			}

			if policy.GetTagTemplates()&inputtype.TEMPLATE_ACL_EDGE != 0 && thisEnd == ZERO {
				// 产品需求：永远仅统计云外、客户端的地理位置信息，即双侧统计量永远基于客户端视角
				if flow.Country == CHN_ID {
					codes = POLICY_CHN_EDGE_CODES[:]
				} else {
					codes = POLICY_NON_CHN_EDGE_CODES[:]
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

	}
	return p.docs.Slice()
}
