package flow

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func TestPolicyTags(t *testing.T) {
	f := inputtype.TaggedFlow{}
	flowMetricsPeerSrc := &f.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &f.FlowMetricsPeers[inputtype.FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.L3EpcID = 3
	flowMetricsPeerDst.L3EpcID = 4
	flowMetricsPeerSrc.Host = binary.BigEndian.Uint32([]byte{10, 1, 1, 1})
	flowMetricsPeerDst.Host = binary.BigEndian.Uint32([]byte{10, 1, 1, 2})
	flowMetricsPeerSrc.L3DeviceID = 33
	flowMetricsPeerDst.L3DeviceID = 44
	flowMetricsPeerSrc.L3DeviceType = 1
	flowMetricsPeerDst.L3DeviceType = 1
	flowMetricsPeerSrc.DeviceID = 33
	flowMetricsPeerDst.DeviceID = 44
	flowMetricsPeerSrc.DeviceType = 1
	flowMetricsPeerDst.DeviceType = 1
	flowMetricsPeerSrc.IsL2End = true
	flowMetricsPeerDst.IsL2End = true
	flowMetricsPeerSrc.IsL3End = true
	flowMetricsPeerDst.IsL3End = true
	flowMetricsPeerSrc.PacketCount = 10
	flowMetricsPeerDst.PacketCount = 10
	flowMetricsPeerSrc.TCPFlags = 0xff
	flowMetricsPeerDst.TCPFlags = 0xff
	f.GroupIDs0 = []uint32{10, 11}
	f.GroupIDs1 = []uint32{20, 21}
	f.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	f.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	f.InPort = 0x3beef
	f.Proto = layers.IPProtocolTCP
	f.PortDst = 80
	f.StartTime = 1536746971 * time.Second
	f.EndTime = 1536746971 * time.Second
	f.EthType = layers.EthernetTypeIPv4

	f.PolicyData.ActionFlags = inputtype.ACTION_FLOW_COUNTING
	f.PolicyData.Merge([]inputtype.AclAction{
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_FLOW_COUNTING).SetDirections(inputtype.FORWARD).SetTagTemplates(0xFFFF),
		inputtype.AclAction(0).SetACLGID(1).AddActionFlags(inputtype.ACTION_FLOW_COUNTING).SetTagTemplates(0xFFFF),
	}, nil, 10)

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	noPolicyDocs := make([]*app.Document, 0, len(docs))
	policyDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).ACLGID > 0 {
			policyDocs = append(policyDocs, doc.(*app.Document))
		} else {
			noPolicyDocs = append(noPolicyDocs, doc.(*app.Document))
		}
	}

	// 有2个是对称的（含Protocol或TAPType），需要减掉
	expectedCodes := 2*(len(NODE_CODES)) + len(NODE_PORT_CODES)

	expectedCodes += len(EDGE_CODES) + len(TOR_EDGE_PORT_CODES) + len(TOR_EDGE_CODES)
	if len(noPolicyDocs) != expectedCodes {
		t.Error("Tag不正确", len(noPolicyDocs), expectedCodes, noPolicyDocs)
	}
}
