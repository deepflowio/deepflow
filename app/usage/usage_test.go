package usage

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func TestPolicyTags(t *testing.T) {
	m := inputtype.MetaPacket{}
	m.EndpointData = &inputtype.EndpointData{}
	m.EndpointData.SrcInfo = &inputtype.EndpointInfo{}
	m.EndpointData.DstInfo = &inputtype.EndpointInfo{}
	m.EndpointData.SrcInfo.L3EpcId = 3
	m.EndpointData.DstInfo.L3EpcId = 4
	m.EndpointData.SrcInfo.L3DeviceId = 33
	m.EndpointData.DstInfo.L3DeviceId = 44
	m.EndpointData.SrcInfo.L3DeviceType = 1
	m.EndpointData.DstInfo.L3DeviceType = 1
	m.EndpointData.SrcInfo.L2End = true
	m.EndpointData.DstInfo.L2End = true
	m.EndpointData.SrcInfo.L3End = true
	m.EndpointData.DstInfo.L3End = true
	m.EndpointData.SrcInfo.GroupIds = []uint32{10, 11}
	m.EndpointData.DstInfo.GroupIds = []uint32{20, 21}
	m.IpSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	m.IpDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	m.InPort = 0x3beef
	m.Protocol = layers.IPProtocolTCP
	m.PortDst = 80
	m.PacketLen = 123
	m.Timestamp = 1536746971

	m.PolicyData = &inputtype.PolicyData{}
	m.PolicyData.ActionFlags = inputtype.ACTION_PACKET_COUNTING | inputtype.ACTION_PACKET_COUNT_BROKERING
	m.PolicyData.Merge([]inputtype.AclAction{
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNTING).SetTagTemplates(0xFFFF),
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNT_BROKERING).SetTagTemplates(0xFFFF),
	}, nil, 10)

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&m, true)
	policyDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).ACLGID > 0 {
			policyDocs = append(policyDocs, doc.(*app.Document))
		}
	}

	// POLICY_NODE_CODES共2个，一个没NODE字段，所以一共是3个tag组合
	// if len(policyDocs) != 3 {
	//	t.Error("策略Tag不正确", policyDocs)
	// }
}

func TestPolicyTagTemplate(t *testing.T) {
	m := inputtype.MetaPacket{}
	m.EndpointData = &inputtype.EndpointData{}
	m.EndpointData.SrcInfo = &inputtype.EndpointInfo{}
	m.EndpointData.DstInfo = &inputtype.EndpointInfo{}
	m.EndpointData.SrcInfo.L3EpcId = 3
	m.EndpointData.DstInfo.L3EpcId = 4
	m.EndpointData.SrcInfo.L3DeviceId = 33
	m.EndpointData.DstInfo.L3DeviceId = 44
	m.EndpointData.SrcInfo.L3DeviceType = 1
	m.EndpointData.DstInfo.L3DeviceType = 1
	m.EndpointData.SrcInfo.L2End = true
	m.EndpointData.DstInfo.L2End = true
	m.EndpointData.SrcInfo.L3End = true
	m.EndpointData.DstInfo.L3End = true
	m.EndpointData.SrcInfo.GroupIds = []uint32{10, 11}
	m.EndpointData.DstInfo.GroupIds = []uint32{20, 21}
	m.IpSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	m.IpDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	m.InPort = 0x3beef
	m.Protocol = layers.IPProtocolTCP
	m.PortDst = 80
	m.PacketLen = 123
	m.Timestamp = 1536746971

	m.PolicyData = &inputtype.PolicyData{}
	m.PolicyData.ActionFlags = inputtype.ACTION_PACKET_COUNTING | inputtype.ACTION_PACKET_COUNT_BROKERING
	m.PolicyData.Merge([]inputtype.AclAction{
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNTING).SetTagTemplates(inputtype.TEMPLATE_ACL_NODE),
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNTING).SetTagTemplates(inputtype.TEMPLATE_ACL_PORT),
	}, nil, 10)

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&m, true)
	policyDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).ACLGID > 0 {
			policyDocs = append(policyDocs, doc.(*app.Document))
		}
	}

	// POLICY_NODE_CODES共2个，一个没NODE字段，所以一共是3个tag组合
	// if len(policyDocs) != 3 {
	//	t.Error("标签策略Tag不正确", policyDocs)
	// }
}
