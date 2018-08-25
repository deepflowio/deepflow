package flowgenerator

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const DEFAULT_QUEUE_LEN = 200
const DEFAULT_INTERVAL_SEC_HIGH = 60
const DEFAULT_INTERVAL_SEC_LOW = 10
const DEFAULT_DURATION_MSEC = time.Millisecond * 123
const DEFAULT_PKT_LEN = 128

func getDefaultPacket() *MetaPacket {
	src, _ := net.ParseMAC("12:34:56:78:9A:BC")
	dst, _ := net.ParseMAC("21:43:65:87:A9:CB")
	return &MetaPacket{
		Timestamp: time.Duration(time.Now().UnixNano()),
		Exporter:  IpToUint32(net.ParseIP("192.168.1.1")),
		InPort:    65533,
		MacSrc:    MacIntFromBytes(src),
		MacDst:    MacIntFromBytes(dst),
		PacketLen: DEFAULT_PKT_LEN,
		Protocol:  6,
		IpSrc:     IpToUint32(net.ParseIP("8.8.8.8").To4()),
		IpDst:     IpToUint32(net.ParseIP("114.114.114.114").To4()),
		PortSrc:   12345,
		PortDst:   22,
		TcpData:   &MetaPacketTcpHeader{Flags: TCP_SYN},
		EndpointData: &EndpointData{
			SrcInfo: &EndpointInfo{
				L2EpcId:  -1,
				L3EpcId:  -1,
				GroupIds: make([]uint32, 10),
				HostIp:   0x01010101,
			},
			DstInfo: &EndpointInfo{
				L2EpcId:  -1,
				L3EpcId:  -1,
				GroupIds: make([]uint32, 10),
				HostIp:   0x01010101,
			},
		},
	}
}

func reversePacket(packet *MetaPacket) {
	packet.MacSrc, packet.MacDst = packet.MacDst, packet.MacSrc
	packet.IpSrc, packet.IpDst = packet.IpDst, packet.IpSrc
	packet.PortSrc, packet.PortDst = packet.PortDst, packet.PortSrc
}

func getDefaultFlowGenerator() *FlowGenerator {
	metaPacketHeaderInQueue := NewOverwriteQueue("metaPacketHeaderInQueue", DEFAULT_QUEUE_LEN)
	flowOutQueue := NewOverwriteQueue("flowOutQueue", DEFAULT_QUEUE_LEN)
	return New(metaPacketHeaderInQueue, flowOutQueue, DEFAULT_INTERVAL_SEC_HIGH)
}

func TestNew(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()

	if flowGenerator == nil {
		t.Error("flowGenerator is nil")
	}
	if flowGenerator.forceReportIntervalSec != DEFAULT_INTERVAL_SEC_HIGH {
		t.Errorf("flowGenerator.forceReportIntervalSec is %d, expect %d",
			flowGenerator.forceReportIntervalSec, DEFAULT_INTERVAL_SEC_HIGH)
	}
	if len(flowGenerator.hashMap) != int(HASH_MAP_SIZE) {
		t.Errorf("flowGenerator.hashMap len is %d, expect %d", len(flowGenerator.hashMap), HASH_MAP_SIZE)
	}
}

func TestHandleSynRst(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800, 30, 30, 5, 0, 5})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	flowGenerator.minLoopIntervalSec = 0
	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	flowGenerator.Start()

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	var taggedFlow *TaggedFlow
	taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_RST {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_RST)
	}
	if taggedFlow.Duration <= DEFAULT_DURATION_MSEC {
		t.Errorf("taggedFlow.Duration is %d, expect more than %d", taggedFlow.Duration, DEFAULT_DURATION_MSEC)
	}
	if taggedFlow.TCPFlags0 != TCP_SYN || taggedFlow.TCPFlags1 != TCP_RST {
		t.Errorf("taggedFlow.TcpFlagsSrc is %d, expect %d", taggedFlow.TCPFlags0, TCP_SYN)
		t.Errorf("taggedFlow.TcpFlagsDst is %d, expect %d", taggedFlow.TCPFlags1, TCP_RST)
	}
	t.Logf("\n%s", taggedFlow)
}

func TestHandleSynFin(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{5, 1800, 0, 30, 5, 0, 5})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	flowGenerator.minLoopIntervalSec = 0

	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_PSH | TCP_ACK
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	go flowGenerator.Start()

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK | TCP_FIN
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	metaPacketHeaderInQueue.(Queue).Put(packet2)

	var taggedFlow *TaggedFlow
	taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_HALF_CLOSE {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_CLOSE)
	}
	if taggedFlow.TCPFlags0 != TCP_SYN|TCP_PSH|TCP_ACK ||
		taggedFlow.TCPFlags1 != TCP_ACK|TCP_FIN {
		t.Errorf("taggedFlow.TCPFlags0 is %x, expect %x", taggedFlow.TCPFlags0, TCP_SYN|TCP_ACK|TCP_PSH)
		t.Errorf("taggedFlow.TCPFlags1 is %x, expect %x", taggedFlow.TCPFlags1, TCP_ACK|TCP_FIN)
	}
	t.Logf("\n%s", taggedFlow)
}

func TestHandleMultiPacket(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800, 30, 30, 5, 0, 5})
	flowGenerator.minLoopIntervalSec = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	var packet *MetaPacket
	var taggedFlow *TaggedFlow
	num := DEFAULT_QUEUE_LEN / 2

	go flowGenerator.Start()

	// direct 0
	for i := 0; i < num; i++ {
		packet = getDefaultPacket()
		packet.TcpData.Flags = TCP_SYN
		packet.PortDst = uint16(i)
		metaPacketHeaderInQueue.(Queue).Put(packet)
	}

	// direct 1
	for i := 0; i < num; i++ {
		packet = getDefaultPacket()
		packet.TcpData.Flags = TCP_RST
		packet.PortDst = uint16(i)
		reversePacket(packet)
		metaPacketHeaderInQueue.(Queue).Put(packet)
	}

	for i := 0; i < num; i++ {
		taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
		if taggedFlow.TotalPacketCount0 != 1 ||
			taggedFlow.TotalPacketCount1 != 1 {
			t.Error("taggedFlow.TotalPacketCount0 and taggedFlow.TotalPacketCount1 are not 1")
		}
	}
	if flowGenerator.stats.TotalNumFlows != uint64(num) {
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect %d", flowGenerator.stats.TotalNumFlows, num)
	}
	if flowGenerator.stats.CurrNumFlows != 0 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect %d", flowGenerator.stats.CurrNumFlows, 0)
	}
}

func TestGetKeyL3Hash(t *testing.T) {
	flowKey := &FlowKey{}

	flowKey.IPSrc = *NewIPFromString("192.168.1.123")
	flowKey.IPDst = *NewIPFromString("10.168.1.221")
	hash0 := getKeyL3Hash(flowKey)

	flowKey.IPDst = *NewIPFromString("192.168.1.123")
	flowKey.IPSrc = *NewIPFromString("10.168.1.221")
	hash1 := getKeyL3Hash(flowKey)

	if hash0 != hash1 {
		t.Errorf("symmetric hash values are %d and %d", hash0, hash1)
	}
}

func TestGetKeyL4Hash(t *testing.T) {
	flowKey := &FlowKey{}

	flowKey.Proto = layers.IPProtocolTCP
	flowKey.PortSrc = 12345
	flowKey.PortDst = 22
	hash0 := getKeyL4Hash(flowKey)

	flowKey.Proto = layers.IPProtocolTCP
	flowKey.PortSrc = 22
	flowKey.PortDst = 12345
	hash1 := getKeyL4Hash(flowKey)

	if hash0 != hash1 {
		t.Errorf("symmetric hash values are %d and %d", hash0, hash1)
	}
}

func TestInitFlow(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	packet := getDefaultPacket()
	flowKey := getFlowKey(packet)
	flowExtra, _, _ := flowGenerator.initFlow(packet, flowKey)
	taggedFlow := flowExtra.taggedFlow

	if taggedFlow.FlowID == 0 {
		t.Error("taggedFlow.FlowID is 0 with an active flow")
	}
	if taggedFlow.TotalByteCount0 != uint64(packet.PacketLen) {
		t.Errorf("taggedFlow.TotalByteCount0 is %d, PacketLen is %d", taggedFlow.TotalByteCount0, packet.PacketLen)
	}

	if taggedFlow.MACSrc.Int() != packet.MacSrc || taggedFlow.MACDst.Int() != packet.MacDst {
		t.Errorf("taggedFlow.MacSrc is %d, packet.MacSrc is %d", taggedFlow.MACSrc.Int(), packet.MacSrc)
		t.Errorf("taggedFlow.MacDst is %d, packet.MacDst is %d", taggedFlow.MACDst.Int(), packet.MacDst)
	}
	if taggedFlow.IPSrc.Int() != packet.IpSrc || taggedFlow.IPDst.Int() != packet.IpDst {
		t.Errorf("taggedFlow.IpSrc is %d, packet.IpSrc is %d", taggedFlow.IPSrc.Int(), packet.IpSrc)
		t.Errorf("taggedFlow.IpDst is %d, packet.IpDst is %d", taggedFlow.IPDst.Int(), packet.IpDst)
	}
	if flowKey.Proto != packet.Protocol {
		t.Errorf("flowKey.Proto is %d, packet.Protocol is %d", taggedFlow.Proto, packet.Protocol)
	}
	if taggedFlow.PortSrc != packet.PortSrc || taggedFlow.PortDst != packet.PortDst {
		t.Errorf("taggedFlow.PortSrc is %d, packet.PortSrc is %d", taggedFlow.PortSrc, packet.PortSrc)
		t.Errorf("taggedFlow.PortDst is %d, packet.PortDst is %d", taggedFlow.PortDst, packet.PortDst)
	}
}

func TestPlatformData(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800, 0, 30, 5, 0, 0})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowGenerator.minLoopIntervalSec = 0
	flowOutQueue := flowGenerator.flowOutQueue

	packet1 := getDefaultPacket()
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_HALF_OPEN {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_OPEN)
	}
	if taggedFlow.EpcID0 != -1 || taggedFlow.L3EpcID0 != -1 {
		t.Errorf("taggedFlow.EpcID0 is %d, expect -1", taggedFlow.EpcID0)
		t.Errorf("taggedFlow.L3EpcID0 is %d, expect -1", taggedFlow.L3EpcID0)
	}
	if taggedFlow.Host0 != 0x01010101 {
		t.Errorf("taggedFlow.Host0 is %d, expect %d", taggedFlow.Host0, 0x01010101)
	}
	t.Logf("\n%s", taggedFlow)
}

func TestFlowStateMachine(t *testing.T) {
	flowGenerator := getDefaultFlowGenerator()
	flowExtra := &FlowExtra{}
	taggedFlow := &TaggedFlow{}
	flowExtra.taggedFlow = taggedFlow
	var packetFlags uint8

	taggedFlow.CloseType = CLOSE_TYPE_UNKNOWN
	flowExtra.flowState = FLOW_STATE_OPENING_1

	// test handshake
	taggedFlow.TCPFlags0 = TCP_SYN
	packetFlags = TCP_SYN | TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_OPENING_2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_OPENING_2)
	}
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, false)
	if flowExtra.flowState != FLOW_STATE_ESTABLISHED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_ESTABLISHED)
	}

	// test fin
	taggedFlow.TCPFlags0 = TCP_FIN
	flowExtra.flowState = FLOW_STATE_CLOSING_TX1
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX1 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX1)
	}
	packetFlags = TCP_FIN | TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX2)
	}
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, false)
	if flowExtra.flowState != FLOW_STATE_CLOSED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSED)
	}
}

func TestHandshakePerf(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportIntervalSec = 0
	flowGenerator.minLoopIntervalSec = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC * 2
	packet2.TcpData.Seq = 112
	packet2.TcpData.Ack = 1112
	metaPacketHeaderInQueue.(Queue).Put(packet2)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
	}
	t.Logf("\n%s", taggedFlow)
}

func TestStartStop(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportIntervalSec = 0
	flowGenerator.minLoopIntervalSec = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	flowGenerator.Stop()

	go func() {
		for {
			taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
			t.Logf("\n" + taggedFlow.String())
		}
	}()
	t.Logf("CurrNumFlows is %d", flowGenerator.stats.CurrNumFlows)
}

func TestFlowReverse(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800, 0, 30, 5, 0, 0})
	flowGenerator.forceReportIntervalSec = 0
	flowGenerator.minLoopIntervalSec = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_ACK
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)

	if taggedFlow.TCPFlags0 != 0 && taggedFlow.TCPFlags1 != TCP_SYN|TCP_ACK {
		t.Errorf("taggedFlow.TCPFlags0 is %d, expect %d", taggedFlow.TCPFlags0, 0)
		t.Errorf("taggedFlow.TCPFlags1 is %d, expect %d", taggedFlow.TCPFlags1, TCP_SYN|TCP_ACK)
	}
	t.Logf("\n%s", taggedFlow)
}

func TestForceReport(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportIntervalSec = 0
	flowGenerator.minLoopIntervalSec = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_SYN | TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	metaPacketHeaderInQueue.(Queue).Put(packet2)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)

	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
	}
	t.Logf("\n%s", taggedFlow)
	if flowGenerator.stats.CurrNumFlows != 1 || flowGenerator.stats.TotalNumFlows != 1 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect 1", flowGenerator.stats.CurrNumFlows)
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect 1", flowGenerator.stats.TotalNumFlows)
	}
}

func BenchmarkCleanHashMap(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300, 0, 30, 5, 0, 0})
	flowGenerator.minLoopIntervalSec = 0
	flowCache := flowGenerator.createFlowCache(b.N, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		flowKey := getFlowKey(meta)
		flowExtra, _, _ := flowGenerator.initFlow(meta, flowKey)
		flowGenerator.addFlow(flowCache, flowExtra)
		flowGenerator.cleanTimeoutHashMap(flowGenerator.hashMap, 0, 1)
	}
}

func BenchmarkProcessPacket(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300, 0, 30, 5, 0, 0})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		meta.PortDst += uint16(i)
		flowGenerator.processPacket(meta)
	}
}
