package flowgenerator

import (
	"math/rand"
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
const DEFAULT_INTERVAL_HIGH = 60 * time.Second
const DEFAULT_INTERVAL_LOW = 10 * time.Second
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
		EthType:   layers.EthernetTypeIPv4,
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
				GroupIds: make([]uint32, 0, 10),
				HostIp:   0x01010101,
			},
			DstInfo: &EndpointInfo{
				L2EpcId:  -1,
				L3EpcId:  -1,
				GroupIds: make([]uint32, 0, 10),
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
	metaPacketHeaderInQueue := NewOverwriteQueues("metaPacketHeaderInQueue", 1, DEFAULT_QUEUE_LEN)
	flowOutQueue := NewOverwriteQueue("flowOutQueue", DEFAULT_QUEUE_LEN)
	return New(metaPacketHeaderInQueue, flowOutQueue, FlowGeneratorConfig{60 * time.Second, 64 * 1024, 1024 * 1024}, 0)
}

func TestNew(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()

	if flowGenerator == nil {
		t.Error("flowGenerator is nil")
	}
	if flowGenerator.forceReportInterval != DEFAULT_INTERVAL_HIGH {
		t.Errorf("flowGenerator.forceReportInterval is %d, expect %d",
			flowGenerator.forceReportInterval, DEFAULT_INTERVAL_HIGH)
	}
	if len(flowGenerator.hashMap) != int(HASH_MAP_SIZE) {
		t.Errorf("flowGenerator.hashMap len is %d, expect %d", len(flowGenerator.hashMap), HASH_MAP_SIZE)
	}
}

func TestHandleSynRst(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	flowGenerator.minLoopInterval = 0
	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	flowGenerator.Start()

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_RST {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_RST)
	}
	if taggedFlow.Duration <= DEFAULT_DURATION_MSEC {
		t.Errorf("taggedFlow.Duration is %d, expect more than %d", taggedFlow.Duration, DEFAULT_DURATION_MSEC)
	}
	if taggedFlow.FlowMetricsPeerSrc.TCPFlags != TCP_SYN || taggedFlow.FlowMetricsPeerDst.TCPFlags != TCP_RST {
		t.Errorf("taggedFlow.TcpFlagsSrc is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.TCPFlags, TCP_SYN)
		t.Errorf("taggedFlow.TcpFlagsDst is %d, expect %d", taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_RST)
	}
}

func TestHandleSynFin(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{5, 1800, 0, 30, 5, 0, 5})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	flowGenerator.minLoopInterval = 0

	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_PSH | TCP_ACK
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK | TCP_FIN
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)

	go flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_HALF_CLOSE {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_CLOSE)
	}
	if taggedFlow.FlowMetricsPeerSrc.TCPFlags != TCP_SYN|TCP_PSH|TCP_ACK ||
		taggedFlow.FlowMetricsPeerDst.TCPFlags != TCP_ACK|TCP_FIN {
		t.Errorf("taggedFlow.TCPFlags0 is %x, expect %x", taggedFlow.FlowMetricsPeerSrc.TCPFlags, TCP_SYN|TCP_ACK|TCP_PSH)
		t.Errorf("taggedFlow.TCPFlags1 is %x, expect %x", taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_ACK|TCP_FIN)
	}
}

func TestGetKeyL3Hash(t *testing.T) {
	flowKey := &FlowKey{}

	flowKey.IPSrc = IPv4Int(NewIPFromString("192.168.1.123").Int())
	flowKey.IPDst = IPv4Int(NewIPFromString("10.168.1.221").Int())
	hash0 := getKeyL3Hash(flowKey)

	flowKey.IPDst = IPv4Int(NewIPFromString("192.168.1.123").Int())
	flowKey.IPSrc = IPv4Int(NewIPFromString("10.168.1.221").Int())
	hash1 := getKeyL3Hash(flowKey)

	if hash0 != hash1 {
		t.Errorf("symmetric hash values are %d and %d", hash0, hash1)
	}
}

func TestGetKeyL4Hash(t *testing.T) {
	flowKey := &FlowKey{}
	basis := rand.Uint32()

	flowKey.Proto = layers.IPProtocolTCP
	flowKey.PortSrc = 12345
	flowKey.PortDst = 22
	hash0 := getKeyL4Hash(flowKey, basis)

	flowKey.PortSrc, flowKey.PortDst = flowKey.PortDst, flowKey.PortSrc
	hash1 := getKeyL4Hash(flowKey, basis)

	if hash0 != hash1 {
		t.Errorf("symmetric hash values are %d and %d", hash0, hash1)
	}
}

func TestInitFlow(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	packet := getDefaultPacket()
	flowKey := flowGenerator.genFlowKey(packet)
	flowExtra, _, _ := flowGenerator.initTcpFlow(packet, flowKey)
	taggedFlow := flowExtra.taggedFlow

	if taggedFlow.FlowID == 0 {
		t.Error("taggedFlow.FlowID is 0 with an active flow")
	}
	if taggedFlow.FlowMetricsPeerSrc.TotalByteCount != uint64(packet.PacketLen) {
		t.Errorf("taggedFlow.TotalByteCount0 is %d, PacketLen is %d", taggedFlow.FlowMetricsPeerSrc.TotalByteCount, packet.PacketLen)
	}

	if taggedFlow.MACSrc != packet.MacSrc || taggedFlow.MACDst != packet.MacDst {
		t.Errorf("taggedFlow.MacSrc is %d, packet.MacSrc is %d", taggedFlow.MACSrc, packet.MacSrc)
		t.Errorf("taggedFlow.MacDst is %d, packet.MacDst is %d", taggedFlow.MACDst, packet.MacDst)
	}
	if taggedFlow.IPSrc != packet.IpSrc || taggedFlow.IPDst != packet.IpDst {
		t.Errorf("taggedFlow.IpSrc is %d, packet.IpSrc is %d", taggedFlow.IPSrc, packet.IpSrc)
		t.Errorf("taggedFlow.IpDst is %d, packet.IpDst is %d", taggedFlow.IPDst, packet.IpDst)
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
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowGenerator.minLoopInterval = 0
	flowOutQueue := flowGenerator.flowOutQueue

	packet1 := getDefaultPacket()
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_HALF_OPEN {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_OPEN)
	}
	if taggedFlow.FlowMetricsPeerSrc.EpcID != -1 || taggedFlow.FlowMetricsPeerSrc.L3EpcID != -1 {
		t.Errorf("taggedFlow.EpcID0 is %d, expect -1", taggedFlow.FlowMetricsPeerSrc.EpcID)
		t.Errorf("taggedFlow.L3EpcID0 is %d, expect -1", taggedFlow.FlowMetricsPeerSrc.L3EpcID)
	}
	if taggedFlow.FlowMetricsPeerSrc.Host != 0x01010101 {
		t.Errorf("taggedFlow.FlowMetricsPeerSrc.Host is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.Host, 0x01010101)
	}
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
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_SYN
	packetFlags = TCP_SYN | TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true, false)
	if flowExtra.flowState != FLOW_STATE_OPENING_2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_OPENING_2)
	}
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, false, false)
	if flowExtra.flowState != FLOW_STATE_ESTABLISHED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_ESTABLISHED)
	}

	// test fin
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_FIN
	flowExtra.flowState = FLOW_STATE_CLOSING_TX1
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true, false)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX1 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX1)
	}
	packetFlags = TCP_FIN | TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, true, false)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX2)
	}
	packetFlags = TCP_ACK
	flowGenerator.updateFlowStateMachine(flowExtra, packetFlags, false, false)
	if flowExtra.flowState != FLOW_STATE_CLOSED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSED)
	}
}

func TestHandshakePerf(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportInterval = 0
	flowGenerator.minLoopInterval = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC * 2
	packet2.TcpData.Seq = 112
	packet2.TcpData.Ack = 1112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestStartStop(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportInterval = 0
	flowGenerator.minLoopInterval = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	flowGenerator.Stop()

	go func() {
		for {
			flowOutQueue.(Queue).Get()
		}
	}()
	t.Logf("CurrNumFlows is %d", flowGenerator.stats.CurrNumFlows)
}

func TestFlowReverse(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 1800 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	flowGenerator.forceReportInterval = 0
	flowGenerator.minLoopInterval = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_ACK
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)

	if taggedFlow.FlowMetricsPeerDst.TCPFlags != 0 && taggedFlow.FlowMetricsPeerSrc.TCPFlags != TCP_SYN|TCP_ACK {
		// the flow is revesed again because of service ports list
		t.Errorf("taggedFlow.TCPFlags0 is %d, expect %d", taggedFlow.FlowMetricsPeerDst.TCPFlags, 0)
		t.Errorf("taggedFlow.TCPFlags1 is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.TCPFlags, TCP_SYN|TCP_ACK)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestForceReport(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportInterval = 0
	flowGenerator.minLoopInterval = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_SYN | TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)

	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
	}
	if flowGenerator.stats.CurrNumFlows != 1 || flowGenerator.stats.TotalNumFlows != 1 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect 1", flowGenerator.stats.CurrNumFlows)
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect 1", flowGenerator.stats.TotalNumFlows)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpShortFlow(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	flowGenerator.minLoopInterval = 0
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	packet := getDefaultPacket()
	packet.Protocol = layers.IPProtocolUDP
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_TIMEOUT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_TIMEOUT)
	}
	if taggedFlow.Proto != layers.IPProtocolUDP {
		t.Errorf("taggedFlow.Proto is %d, expect %d", taggedFlow.Proto, layers.IPProtocolUDP)
	}
}

func BenchmarkCleanHashMap(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	flowGenerator.minLoopInterval = 0
	flowCache := &FlowCache{capacity: b.N, flowList: NewListFlowExtra()}
	flowGenerator.hashMap[0] = flowCache
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		flowKey := flowGenerator.genFlowKey(meta)
		flowExtra, _, _ := flowGenerator.initTcpFlow(meta, flowKey)
		flowGenerator.addFlow(flowCache, flowExtra)
		flowGenerator.cleanTimeoutHashMap(flowGenerator.hashMap, 0, 1, 0)
	}
	b.Logf("b.N: %d, NonEmptyFlowCacheNum: %d", b.N, flowGenerator.stats.NonEmptyFlowCacheNum)
}

func BenchmarkShortFlowList(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	processBuffer := make([]interface{}, b.N)
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		meta.IpSrc += uint32(i)
		processBuffer[i] = meta
	}
	b.ResetTimer()
	flowGenerator.packetHandler.Add(1)
	flowGenerator.processPackets(processBuffer, b.N)
	b.StopTimer()
	maxFlowListLen := 0
	for _, flowCache := range flowGenerator.hashMap[0:] {
		if flowCache != nil {
			if flowCache.flowList.Len() > maxFlowListLen {
				maxFlowListLen = flowCache.flowList.Len()
			}
		}
	}
	b.Logf("b.N: %d, maxFlowListLen: %d", b.N, maxFlowListLen)
}

func BenchmarkLongFlowList(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	processBuffer := make([]interface{}, b.N)
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		meta.PortDst += uint16(i)
		processBuffer[i] = meta
	}
	b.ResetTimer()
	flowGenerator.packetHandler.Add(1)
	flowGenerator.processPackets(processBuffer, b.N)
	b.StopTimer()
	maxFlowListLen := 0
	for _, flowCache := range flowGenerator.hashMap[0:] {
		if flowCache != nil {
			if flowCache.flowList.Len() > maxFlowListLen {
				maxFlowListLen = flowCache.flowList.Len()
			}
		}
	}
	b.Logf("b.N: %d, maxFlowListLen: %d, CurrNumFlows: %d", b.N, maxFlowListLen, flowGenerator.stats.CurrNumFlows)
}
