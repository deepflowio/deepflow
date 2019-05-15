package consolelog

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func TestTagsSSH(t *testing.T) {
	f := inputtype.TaggedFlow{}
	f.CloseType = inputtype.CloseTypeTCPFin
	f.FlowMetricsPeerSrc.L3EpcID = 3
	f.FlowMetricsPeerDst.L3EpcID = 4
	f.FlowMetricsPeerSrc.IsL2End = true
	f.FlowMetricsPeerDst.IsL2End = true
	f.FlowMetricsPeerSrc.IsL3End = true
	f.FlowMetricsPeerDst.IsL3End = true
	f.FlowMetricsPeerSrc.PacketCount = 10
	f.FlowMetricsPeerDst.PacketCount = 10
	f.FlowMetricsPeerSrc.TCPFlags = 0xff
	f.FlowMetricsPeerDst.TCPFlags = 0xff
	f.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	f.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	f.InPort = 65536
	f.Proto = layers.IPProtocolTCP
	f.PortDst = 22
	f.EndTime = 1536746971 * time.Second
	f.PolicyData = &inputtype.PolicyData{}
	f.PolicyData.ActionFlags = inputtype.ACTION_FLOW_MISC_COUNTING

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	logDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).Code == CODES[0] {
			logDocs = append(logDocs, doc.(*app.Document))
		}
	}

	if len(logDocs) != len(CODES) {
		t.Error("22端口Tag不正确", logDocs)
	}
}

func TestTagsTelnet(t *testing.T) {
	f := inputtype.TaggedFlow{}
	f.CloseType = inputtype.CloseTypeTCPFin
	f.FlowMetricsPeerSrc.L3EpcID = 3
	f.FlowMetricsPeerDst.L3EpcID = 4
	f.FlowMetricsPeerSrc.IsL2End = true
	f.FlowMetricsPeerDst.IsL2End = true
	f.FlowMetricsPeerSrc.IsL3End = true
	f.FlowMetricsPeerDst.IsL3End = true
	f.FlowMetricsPeerSrc.PacketCount = 10
	f.FlowMetricsPeerDst.PacketCount = 10
	f.FlowMetricsPeerSrc.TCPFlags = 0xff
	f.FlowMetricsPeerDst.TCPFlags = 0xff
	f.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	f.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	f.InPort = 65536
	f.Proto = layers.IPProtocolTCP
	f.PortDst = 23
	f.EndTime = 1536746971 * time.Second
	f.PolicyData = &inputtype.PolicyData{}
	f.PolicyData.ActionFlags = inputtype.ACTION_FLOW_MISC_COUNTING

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	logDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).Code == CODES[0] {
			logDocs = append(logDocs, doc.(*app.Document))
		}
	}

	if len(logDocs) != len(CODES) {
		t.Error("23端口Tag不正确", logDocs)
	}
}

func TestTagsRDP(t *testing.T) {
	f := inputtype.TaggedFlow{}
	f.CloseType = inputtype.CloseTypeTCPFin
	f.FlowMetricsPeerSrc.L3EpcID = 3
	f.FlowMetricsPeerDst.L3EpcID = 4
	f.FlowMetricsPeerSrc.IsL2End = true
	f.FlowMetricsPeerDst.IsL2End = true
	f.FlowMetricsPeerSrc.IsL3End = true
	f.FlowMetricsPeerDst.IsL3End = true
	f.FlowMetricsPeerSrc.PacketCount = 10
	f.FlowMetricsPeerDst.PacketCount = 10
	f.FlowMetricsPeerSrc.TCPFlags = 0xff
	f.FlowMetricsPeerDst.TCPFlags = 0xff
	f.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	f.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	f.InPort = 65536
	f.Proto = layers.IPProtocolTCP
	f.PortDst = 3389
	f.EndTime = 1536746971 * time.Second
	f.PolicyData = &inputtype.PolicyData{}
	f.PolicyData.ActionFlags = inputtype.ACTION_FLOW_MISC_COUNTING

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	logDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).Code == CODES[0] {
			logDocs = append(logDocs, doc.(*app.Document))
		}
	}

	if len(logDocs) != len(CODES) {
		t.Error("3389端口Tag不正确", logDocs)
	}
}

func TestTagsAbnormalClosetype(t *testing.T) {
	f := inputtype.TaggedFlow{}
	f.CloseType = inputtype.CloseTypeForcedReport
	f.FlowMetricsPeerSrc.L3EpcID = 3
	f.FlowMetricsPeerDst.L3EpcID = 4
	f.FlowMetricsPeerSrc.IsL2End = true
	f.FlowMetricsPeerDst.IsL2End = true
	f.FlowMetricsPeerSrc.IsL3End = true
	f.FlowMetricsPeerDst.IsL3End = true
	f.FlowMetricsPeerSrc.PacketCount = 10
	f.FlowMetricsPeerDst.PacketCount = 10
	f.FlowMetricsPeerSrc.TCPFlags = 0xff
	f.FlowMetricsPeerDst.TCPFlags = 0xff
	f.IPSrc = binary.BigEndian.Uint32([]byte{10, 10, 10, 2})
	f.IPDst = binary.BigEndian.Uint32([]byte{10, 10, 10, 3})
	f.InPort = 65536
	f.Proto = layers.IPProtocolTCP
	f.PortDst = 3389
	f.EndTime = 1536746971 * time.Second
	f.PolicyData = &inputtype.PolicyData{}
	f.PolicyData.ActionFlags = inputtype.ACTION_FLOW_MISC_COUNTING

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	logDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).Code == CODES[0] {
			logDocs = append(logDocs, doc.(*app.Document))
		}
	}

	if len(logDocs) != 0 {
		t.Error("ForcedReport流量不需要记录", logDocs)
	}
}

func TestTagsWrongPort(t *testing.T) {
	f := inputtype.TaggedFlow{}
	f.CloseType = inputtype.CloseTypeForcedReport
	f.PortDst = 1
	f.PolicyData = &inputtype.PolicyData{}

	processor := NewProcessor()
	processor.Prepare()
	docs := processor.Process(&f, true)
	logDocs := make([]*app.Document, 0, len(docs))

	for _, doc := range docs {
		if doc.(*app.Document).Tag.(*outputtype.Tag).Code == CODES[0] {
			logDocs = append(logDocs, doc.(*app.Document))
		}
	}

	if len(logDocs) != 0 {
		t.Error("SSH/Telnet/RDP之外的流量不需要记录", logDocs)
	}
}
