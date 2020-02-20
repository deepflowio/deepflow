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
	m := inputtype.TaggedFlow{}
	flowMetricsPeerSrc := &m.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &m.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.L3EpcID = 3
	flowMetricsPeerDst.L3EpcID = 4
	flowMetricsPeerSrc.L3DeviceID = 33
	flowMetricsPeerDst.L3DeviceID = 44
	flowMetricsPeerSrc.L3DeviceType = 1
	flowMetricsPeerDst.L3DeviceType = 1
	flowMetricsPeerSrc.IsL2End = true
	flowMetricsPeerDst.IsL2End = true
	flowMetricsPeerSrc.IsL3End = true
	flowMetricsPeerDst.IsL3End = true
	flowMetricsPeerSrc.TickPacketCount = 10
	flowMetricsPeerDst.TickPacketCount = 20
	flowMetricsPeerSrc.TickByteCount = 1000
	flowMetricsPeerDst.TickByteCount = 2000
	m.GroupIDs0 = []uint32{10, 11}
	m.GroupIDs1 = []uint32{20, 21}
	m.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	m.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	m.InPort = 0x3beef
	m.Proto = layers.IPProtocolTCP
	m.PortDst = 80
	m.PacketStatTime = 1536746971

	m.PolicyData.ActionFlags = inputtype.ACTION_PACKET_COUNTING
	m.PolicyData.Merge([]inputtype.AclAction{
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNTING).SetTagTemplates(0xFFFF),
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_PACKET_COUNTING).SetTagTemplates(0xFFFF),
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
	m := inputtype.TaggedFlow{}
	flowMetricsPeerSrc := &m.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &m.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.L3EpcID = 3
	flowMetricsPeerDst.L3EpcID = 4
	flowMetricsPeerSrc.L3DeviceID = 33
	flowMetricsPeerDst.L3DeviceID = 44
	flowMetricsPeerSrc.L3DeviceType = 1
	flowMetricsPeerDst.L3DeviceType = 1
	flowMetricsPeerSrc.IsL2End = true
	flowMetricsPeerDst.IsL2End = true
	flowMetricsPeerSrc.IsL3End = true
	flowMetricsPeerDst.IsL3End = true
	flowMetricsPeerSrc.TickPacketCount = 10
	flowMetricsPeerDst.TickPacketCount = 20
	flowMetricsPeerSrc.TickByteCount = 1000
	flowMetricsPeerDst.TickByteCount = 2000
	m.GroupIDs0 = []uint32{10, 11}
	m.GroupIDs1 = []uint32{20, 21}
	m.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	m.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	m.InPort = 0x3beef
	m.Proto = layers.IPProtocolTCP
	m.PortDst = 80
	m.PacketStatTime = 1536746971

	m.PolicyData.ActionFlags = inputtype.ACTION_PACKET_COUNTING
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
