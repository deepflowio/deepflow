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

	"gitlab.x.lan/yunshan/droplet/queue"
)

const DEFAULT_QUEUE_LEN = 256
const DEFAULT_INTERVAL_HIGH = 60 * time.Second
const DEFAULT_DURATION_MSEC = time.Millisecond * 10
const DEFAULT_PKT_LEN = 128

var testTimeoutConfig = TimeoutConfig{
	Opening:         time.Millisecond * 10,
	Established:     TIMEOUT_ESTABLISHED,
	Closing:         time.Millisecond * 10,
	EstablishedRst:  time.Millisecond * 10,
	Exception:       time.Millisecond * 10,
	ClosedFin:       TIMEOUT_CLOSED_FIN,
	SingleDirection: time.Millisecond * 10,
}

func flowGeneratorInit(queueSize int, flushTicker bool) (*FlowGenerator, QueueWriter, QueueReader, QueueReader) {
	if queueSize <= 0 {
		queueSize = DEFAULT_QUEUE_LEN
	}

	flowGeneratorCount = 1
	_TIME_SLOT_UNIT = time.Millisecond
	_PACKET_STAT_INTERVAL = time.Millisecond
	_FLOW_STAT_INTERVAL = time.Millisecond * 100
	hashMapSize = uint64(queueSize / 8)
	reportTolerance = time.Millisecond * 4
	ignoreTorMac = false
	ignoreL2End = false
	innerFlowGeo = testFlowGeo
	SetTimeout(testTimeoutConfig)
	manager := queue.NewManager()
	flowOutQueue := manager.NewQueues("flowOutQueue", queueSize, 1, 1)
	meteringAppQueues := manager.NewQueues("3-meta-packet-to-metering-app", queueSize, 1, 1)
	var inputPacketQueue *queue.MultiQueue = nil
	if flushTicker {
		inputPacketQueue = manager.NewQueues("inputPacketQueue", queueSize, 1, 1, OptionFlushIndicator(time.Millisecond*4))
	} else {
		inputPacketQueue = manager.NewQueues("inputPacketQueue", queueSize, 1, 1)
	}
	return New(
		inputPacketQueue.Readers()[0], meteringAppQueues.Writers()[0], flowOutQueue.Writers()[0],
		queueSize, 0, time.Millisecond,
	), inputPacketQueue.Writers()[0], flowOutQueue.Readers()[0], meteringAppQueues.Readers()[0]
}

func getDefaultPacket() *MetaPacket {
	src, _ := net.ParseMAC("12:34:56:78:9A:BC")
	dst, _ := net.ParseMAC("21:43:65:87:A9:CB")
	return &MetaPacket{
		Timestamp: time.Duration(time.Now().UnixNano()),
		Exporter:  IpToUint32(net.ParseIP("192.168.1.1").To4()),
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
				L2EpcId:  EPC_FROM_DEEPFLOW,
				L3EpcId:  1,
				GroupIds: make([]uint32, 0, 10),
				HostIp:   0x01010101,
			},
			DstInfo: &EndpointInfo{
				L2EpcId:  EPC_FROM_DEEPFLOW,
				L3EpcId:  EPC_FROM_INTERNET,
				GroupIds: make([]uint32, 0, 10),
				HostIp:   0x01010101,
			},
		},
		PolicyData: &PolicyData{ActionFlags: ACTION_GEO_POSITIONING | ACTION_PACKET_COUNTING | ACTION_TCP_FLOW_PERF_COUNTING},
	}
}

func getUdpDefaultPacket() *MetaPacket {
	packet := getDefaultPacket()
	packet.Protocol = 17
	packet.TcpData = nil
	packet.PortSrc = 80
	packet.PortDst = 8080
	return packet
}

func generateAclAction(id ACLID, actionFlags ActionFlag) AclAction {
	return AclAction(id).AddActionFlags(actionFlags).AddDirections(FORWARD).AddTagTemplates(TEMPLATE_EDGE_PORT)
}

func reversePacket(packet *MetaPacket) {
	packet.MacSrc, packet.MacDst = packet.MacDst, packet.MacSrc
	packet.IpSrc, packet.IpDst = packet.IpDst, packet.IpSrc
	packet.PortSrc, packet.PortDst = packet.PortDst, packet.PortSrc
	packet.L2End0, packet.L2End1 = packet.L2End1, packet.L2End0
	packet.EndpointData = packet.EndpointData.ReverseData()
}

func TestNew(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, _, _, _ := flowGeneratorInit(0, true)
	_FLOW_STAT_INTERVAL = 60 * time.Second

	if _FLOW_STAT_INTERVAL != DEFAULT_INTERVAL_HIGH {
		t.Errorf("flowGenerator._FLOW_STAT_INTERVAL is %d, expect %d",
			_FLOW_STAT_INTERVAL, DEFAULT_INTERVAL_HIGH)
	}
	if len(flowGenerator.flowMap.hashSlotHead) != int(hashMapSize) {
		t.Errorf("flowGenerator.flowMap.hashSlotHead len is %d, expect %d", len(flowGenerator.flowMap.hashSlotHead), hashMapSize)
	}
}

func TestTunnelMatch(t *testing.T) {
	metaTunnelInfo := &TunnelInfo{Type: 1, Src: 0, Dst: 2, Id: 1}
	flowTunnelInfo := &TunnelInfo{Type: 1, Src: 1, Dst: 3, Id: 1}
	if ok := tunnelMatch(metaTunnelInfo, flowTunnelInfo); ok {
		t.Errorf("TunnelMatch return %t, expect false", ok)
	}

	flowTunnelInfo2 := &TunnelInfo{}
	if ok := tunnelMatch(nil, flowTunnelInfo2); !ok {
		t.Errorf("TunnelMatch return %t, expect true", ok)
	}

	flowTunnelInfo3 := &TunnelInfo{Type: 1, Src: 1, Dst: 3, Id: 1}
	if ok := tunnelMatch(nil, flowTunnelInfo3); ok {
		t.Errorf("TunnelMatch return %t, expect false", ok)
	}
}

func getFromQueue(q QueueReader) interface{} {
	var e interface{} = nil
	for e == nil {
		e = q.Get()
	}
	return e
}

func TestHandleSynRst(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	_FLOW_STAT_INTERVAL = 60 * time.Second

	packet0 := getDefaultPacket()
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	inputPacketQueue.Put(packet1)

	flowGenerator.Start()

	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeTCPServerRst {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeTCPServerRst)
		t.Errorf("%s\n", taggedFlow)
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
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	_FLOW_STAT_INTERVAL = 60 * time.Second

	packet0 := getDefaultPacket()
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_PSH | TCP_ACK
	inputPacketQueue.Put(packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK | TCP_FIN
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	inputPacketQueue.Put(packet2)

	flowGenerator.Start()

	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeClientHalfClose {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeClientHalfClose)
	}
	if taggedFlow.FlowMetricsPeerSrc.TCPFlags != TCP_SYN|TCP_PSH|TCP_ACK ||
		taggedFlow.FlowMetricsPeerDst.TCPFlags != TCP_ACK|TCP_FIN {
		t.Errorf("taggedFlow.TCPFlags0 is %x, expect %x", taggedFlow.FlowMetricsPeerSrc.TCPFlags, TCP_SYN|TCP_ACK|TCP_PSH)
		t.Errorf("taggedFlow.TCPFlags1 is %x, expect %x", taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_ACK|TCP_FIN)
	}
}

func TestPlatformData(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	packet1 := getDefaultPacket()
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	packet1.Timestamp = packet1.Timestamp / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL // 避免ForceReport
	inputPacketQueue.Put(packet1)

	flowGenerator.Start()

	expectEpcID0, expectL3EpcId := int32(EPC_FROM_DEEPFLOW), int32(1)
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeServerHalfOpen {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeServerHalfOpen)
	}
	if taggedFlow.FlowMetricsPeerSrc.EpcID != expectEpcID0 || taggedFlow.FlowMetricsPeerSrc.L3EpcID != expectL3EpcId {
		t.Errorf("taggedFlow.EpcID0 is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.EpcID, expectEpcID0)
		t.Errorf("taggedFlow.L3EpcID0 is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.L3EpcID, expectL3EpcId)
	}
	if taggedFlow.FlowMetricsPeerSrc.Host != 0x01010101 {
		t.Errorf("taggedFlow.FlowMetricsPeerSrc.Host is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.Host, 0x01010101)
	}
}

func TestFlowStateMachine(t *testing.T) {
	flowGenerator, _, _, _ := flowGeneratorInit(0, true)
	flowExtra := &FlowExtra{}
	taggedFlow := &TaggedFlow{}
	flowExtra.taggedFlow = taggedFlow
	var packetFlags uint8

	taggedFlow.CloseType = CloseTypeUnknown
	flowExtra.flowState = FLOW_STATE_OPENING_1

	// test handshake
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_SYN
	packetFlags = TCP_SYN | TCP_ACK
	flowGenerator.flowMap.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_OPENING_2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_OPENING_2)
	}
	packetFlags = TCP_ACK
	flowGenerator.flowMap.updateFlowStateMachine(flowExtra, packetFlags, false)
	if flowExtra.flowState != FLOW_STATE_ESTABLISHED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_ESTABLISHED)
	}

	// test fin
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_FIN
	flowExtra.flowState = FLOW_STATE_CLOSING_TX1
	packetFlags = TCP_ACK
	flowGenerator.flowMap.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX1 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX1)
	}
	packetFlags = TCP_FIN | TCP_ACK
	flowGenerator.flowMap.updateFlowStateMachine(flowExtra, packetFlags, true)
	if flowExtra.flowState != FLOW_STATE_CLOSING_TX2 {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING_TX2)
	}
	packetFlags = TCP_ACK
	flowGenerator.flowMap.updateFlowStateMachine(flowExtra, packetFlags, false)
	if flowExtra.flowState != FLOW_STATE_CLOSED {
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSED)
	}
}

func TestHandshakePerf(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	inputPacketQueue.Put(packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC * 2
	packet2.TcpData.Seq = 112
	packet2.TcpData.Ack = 1112
	inputPacketQueue.Put(packet2)

	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeForcedReport {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeForcedReport)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestStartStop(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	inputPacketQueue.Put(packet0)

	flowGenerator.Stop()

	go func() {
		for {
			flowOutQueue.Get()
		}
	}()
	t.Logf("CurrNumFlows is %d", flowGenerator.flowMap.size)
}

func TestReverseInNewCycle(t *testing.T) {
	flowGenerator, _, _, _ := flowGeneratorInit(0, true)

	policyData0 := new(PolicyData)
	policyData0.Merge([]AclAction{generateAclAction(10, ACTION_PACKET_COUNTING)}, nil, 10)
	packet0 := getDefaultPacket()
	packet0.PolicyData = policyData0

	policyData1 := new(PolicyData)
	policyData1.Merge([]AclAction{generateAclAction(11, ACTION_PACKET_COUNTING)}, nil, 11)
	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	reversePacket(packet1)
	packet1.Direction = SERVER_TO_CLIENT
	packet1.PolicyData = policyData1

	flowExtra := &FlowExtra{}
	flowGenerator.flowMap.initFlow(flowExtra, packet0, packet0.Timestamp)
	flowExtra.packetInCycle = false
	flowGenerator.flowMap.updateFlow(flowExtra, packet1)

	direction := flowExtra.taggedFlow.PolicyData.AclActions[0].GetDirections()
	aclid := flowExtra.taggedFlow.PolicyData.ACLID
	if direction != BACKWARD || aclid != 11 {
		t.Errorf("taggedFlow.PolicyData.AclActions[0].GetDirections() is %d, expect %d", direction, BACKWARD)
		t.Errorf("taggedFlow.PolicyData.GetACLID is %d, expect %d", aclid, 11)
		t.Errorf("\n%s", flowExtra.taggedFlow)
	}
}

func TestForceReport(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	packet0 := getDefaultPacket()
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	inputPacketQueue.Put(packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	inputPacketQueue.Put(packet2)

	flowGenerator.Start()

	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeForcedReport {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeForcedReport)
	}
	if flowGenerator.flowMap.totalFlow != 1 || flowGenerator.flowMap.size != 1 {
		t.Errorf("flowGenerator.flowMap.size is %d, expect 1", flowGenerator.flowMap.size)
		t.Errorf("flowGenerator.flowMap.totalFlow is %d, expect 1", flowGenerator.flowMap.totalFlow)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpShortFlow(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	packet := getDefaultPacket()
	packet.Protocol = layers.IPProtocolUDP
	inputPacketQueue.Put(packet)
	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeTimeout {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeTimeout)
	}
	if taggedFlow.Proto != layers.IPProtocolUDP {
		t.Errorf("taggedFlow.Proto is %d, expect %d", taggedFlow.Proto, layers.IPProtocolUDP)
	}
}

func TestEthOthersShortFlow(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)

	packet := getDefaultPacket()
	packet.Protocol = 0
	packet.EthType = layers.EthernetTypeARP
	inputPacketQueue.Put(packet)
	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeTimeout {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeTimeout)
	}
	if taggedFlow.EthType != layers.EthernetTypeARP {
		t.Errorf("taggedFlow.EthType is %d, expect %d", taggedFlow.EthType, layers.EthernetTypeARP)
	}
}

func TestInPortEqualTor(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	ignoreTorMac = true

	packet0 := getDefaultPacket()
	packet0.InPort = 0x30000
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	dst, _ := net.ParseMAC("21:43:65:AA:AA:AA")
	packet1.MacDst = MacIntFromBytes(dst)
	packet1.InPort = 0x30000
	packet1.TcpData.Flags = TCP_RST
	reversePacket(packet1)
	inputPacketQueue.Put(packet1)
	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if cnt := taggedFlow.FlowMetricsPeerDst.PacketCount; cnt != 1 {
		t.Errorf("taggedFlow.FlowMetricsPeerDst.PacketCount is %d, expect 1", cnt)
	}
}

func TestIgnoreL2End(t *testing.T) {
	ignoreL2End = false
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, time.Millisecond * 10})

	packet0 := getDefaultPacket()
	packet0.InPort = 0x31234
	inputPacketQueue.Put(packet0)

	packet1 := getDefaultPacket()
	dst, _ := net.ParseMAC("21:43:65:AA:AA:AA")
	packet1.MacDst = MacIntFromBytes(dst)
	packet1.InPort = 0x31234
	packet1.L2End0 = true
	packet1.L2End1 = false
	packet1.TcpData.Flags = TCP_RST
	reversePacket(packet1)
	inputPacketQueue.Put(packet1)
	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if cnt := taggedFlow.FlowMetricsPeerDst.PacketCount; cnt != 1 {
		t.Errorf("taggedFlow.FlowMetricsPeerDst.PacketCount is %d, expect 1", cnt)
	}
}

func TestDoubleFinFromServer(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, _ := flowGeneratorInit(0, true)
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, time.Millisecond * 10})
	// SYN
	packet0 := getDefaultPacket()
	packet0.Timestamp = packet0.Timestamp / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL // 避免ForceReport
	packetTimestamp := packet0.Timestamp
	inputPacketQueue.Put(packet0)
	// SYN | ACK
	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp = packetTimestamp
	reversePacket(packet1)
	inputPacketQueue.Put(packet1)
	// ACK
	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp = packetTimestamp
	inputPacketQueue.Put(packet2)
	// FIN
	packet3 := getDefaultPacket()
	packet3.TcpData.Flags = TCP_FIN
	packet3.Timestamp = packetTimestamp
	reversePacket(packet3)
	inputPacketQueue.Put(packet3)
	// FIN
	packet4 := getDefaultPacket()
	packet4.TcpData.Flags = TCP_FIN
	packet4.Timestamp = packetTimestamp
	reversePacket(packet4)
	inputPacketQueue.Put(packet4)

	flowGenerator.Start()
	taggedFlow := getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.Flow.CloseType != CloseTypeClientHalfClose { // CloseTypeClientHalfClose是服务端发送FIN，而客户端未发送FIN
		t.Errorf("taggedFlow.Flow.CloseType is %d, expect %d", taggedFlow.Flow.CloseType, CloseTypeClientHalfClose)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestStatOutput(t *testing.T) {
	flowGenerator, inputPacketQueue, flowOutQueue, meteringAppQueue := flowGeneratorInit(0, true)
	_FLOW_STAT_INTERVAL = DEFAULT_DURATION_MSEC

	// 两个同样时间槽的同向包
	packet0 := getDefaultPacket()
	packet0.Timestamp = packet0.Timestamp/_FLOW_STAT_INTERVAL*_FLOW_STAT_INTERVAL - time.Millisecond // 构造ForceReport
	timestamp0 := packet0.Timestamp

	packet1 := getDefaultPacket()
	packet1.Timestamp = timestamp0

	inputPacketQueue.Put(packet0)
	inputPacketQueue.Put(packet1)

	// 两个同样时间槽的不同向包，时间早于之前的包
	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_SYN | TCP_ACK
	packet2.Timestamp = timestamp0 - _PACKET_STAT_INTERVAL
	timestamp2 := packet2.Timestamp
	reversePacket(packet2)

	packet3 := getDefaultPacket()
	packet3.TcpData.Flags = TCP_ACK
	packet3.Timestamp = timestamp2

	inputPacketQueue.Put(packet2)
	inputPacketQueue.Put(packet3)

	// 一个反向的包，会终结Flow，时间晚于之前的包
	packet4 := getDefaultPacket()
	packet4.TcpData.Flags = TCP_RST
	packet4.Timestamp = timestamp0 + DEFAULT_DURATION_MSEC
	timestamp4 := packet4.Timestamp
	reversePacket(packet4)
	inputPacketQueue.Put(packet4)

	flowGenerator.Start()

	// 包统计数据
	taggedFlow := getFromQueue(meteringAppQueue).(*TaggedFlow)
	if taggedFlow.PacketStatTime != timestamp0 ||
		taggedFlow.FlowMetricsPeerSrc.TickPacketCount != 2 ||
		taggedFlow.FlowMetricsPeerDst.TickPacketCount != 0 {
		t.Errorf("首个包统计 taggedFlow.PacketStatTime is %dms, expect %dms", taggedFlow.PacketStatTime/_TIME_SLOT_UNIT, timestamp0/_TIME_SLOT_UNIT)
		t.Errorf("首个包统计 taggedFlow.FlowMetricsPeerSrc.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.TickPacketCount, 2)
		t.Errorf("首个包统计 taggedFlow.FlowMetricsPeerDst.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerDst.TickPacketCount, 0)
		t.Errorf("%s\n", taggedFlow)
	}
	taggedFlow = getFromQueue(meteringAppQueue).(*TaggedFlow)
	if taggedFlow.PacketStatTime != timestamp2 ||
		taggedFlow.FlowMetricsPeerSrc.TickPacketCount != 1 ||
		taggedFlow.FlowMetricsPeerDst.TickPacketCount != 1 {
		t.Errorf("第二个包统计 taggedFlow.PacketStatTime is %dms, expect %dms", taggedFlow.PacketStatTime/_TIME_SLOT_UNIT, timestamp2/_TIME_SLOT_UNIT)
		t.Errorf("第二个包统计 taggedFlow.FlowMetricsPeerSrc.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.TickPacketCount, 1)
		t.Errorf("第二个包统计 taggedFlow.FlowMetricsPeerDst.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerDst.TickPacketCount, 1)
		t.Errorf("%s\n", taggedFlow)
	}
	taggedFlow = getFromQueue(meteringAppQueue).(*TaggedFlow)
	if taggedFlow.PacketStatTime != timestamp4 ||
		taggedFlow.FlowMetricsPeerSrc.TickPacketCount != 0 ||
		taggedFlow.FlowMetricsPeerDst.TickPacketCount != 1 {
		t.Errorf("第三个包统计 taggedFlow.PacketStatTime is %dms, expect %dms", taggedFlow.PacketStatTime/_TIME_SLOT_UNIT, timestamp4/_TIME_SLOT_UNIT)
		t.Errorf("第三个包统计 taggedFlow.FlowMetricsPeerSrc.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerSrc.TickPacketCount, 0)
		t.Errorf("第三个包统计 taggedFlow.FlowMetricsPeerDst.TickPacketCount is %d, expect %d", taggedFlow.FlowMetricsPeerDst.TickPacketCount, 1)
		t.Errorf("%s\n", taggedFlow)
	}
	if meteringAppQueue.Len() != 0 {
		t.Errorf("包统计队列中还有残留数据 %d", meteringAppQueue.Len())
	}

	// 流统计数据
	firstForceReportTime := (timestamp0 + _FLOW_STAT_INTERVAL - 1) / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL
	taggedFlow = getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.StartTime != timestamp0 || taggedFlow.EndTime != firstForceReportTime || taggedFlow.CloseType != CloseTypeForcedReport ||
		taggedFlow.FlowMetricsPeerSrc.PacketCount != 3 || taggedFlow.FlowMetricsPeerDst.PacketCount != 1 {
		t.Errorf("首个流统计 Expect: StartTime %d, EndTime %d, CloseType %d, PacketCount0 %d, PacketCount1 %d",
			timestamp0, firstForceReportTime, CloseTypeForcedReport, 3, 1)
		t.Errorf("timestamp 0/2/4: %d %d %d\n", timestamp0, timestamp2, timestamp4)
		t.Errorf("%s\n", taggedFlow)
	}
	taggedFlow = getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.StartTime != firstForceReportTime ||
		taggedFlow.EndTime != firstForceReportTime+_FLOW_STAT_INTERVAL || taggedFlow.CloseType != CloseTypeForcedReport ||
		taggedFlow.FlowMetricsPeerSrc.PacketCount != 0 || taggedFlow.FlowMetricsPeerDst.PacketCount != 1 {
		t.Errorf("第二个个流统计 Expect: StartTime %d, EndTime %d, CloseType %d, PacketCount0 %d, PacketCount1 %d",
			firstForceReportTime, firstForceReportTime+_FLOW_STAT_INTERVAL, CloseTypeForcedReport, 0, 1)
		t.Errorf("timestamp 0/2/4: %d %d %d\n", timestamp0, timestamp2, timestamp4)
		t.Errorf("%s\n", taggedFlow)
	}
	taggedFlow = getFromQueue(flowOutQueue).(*TaggedFlow)
	if taggedFlow.StartTime != firstForceReportTime+_FLOW_STAT_INTERVAL ||
		taggedFlow.EndTime != timestamp4+testTimeoutConfig.EstablishedRst ||
		taggedFlow.CloseType != CloseTypeTCPServerRst {
		t.Errorf("第三个个流统计 Expect: StartTime %d, EndTime %d, CloseType %d, PacketCount0 %d, PacketCount1 %d",
			firstForceReportTime+_FLOW_STAT_INTERVAL, timestamp4+testTimeoutConfig.EstablishedRst, CloseTypeTCPServerRst, 0, 0)
		t.Errorf("%s\n", taggedFlow)
	}
	if flowOutQueue.Len() != 0 {
		t.Errorf("流统计队列中还有残留数据 %d", flowOutQueue.Len())
		taggedFlow = getFromQueue(flowOutQueue).(*TaggedFlow)
		t.Errorf("%s\n", taggedFlow)
	}
}

func BenchmarkFlowMapWithSYNFlood(b *testing.B) {
	packets := make([]MetaPacket, b.N)
	buffer := make([]interface{}, b.N)
	packetTemplate := getDefaultPacket()
	for i := 0; i < b.N; i++ { // 10Mpps
		packets[i] = *packetTemplate
		packets[i].Timestamp = packetTemplate.Timestamp + time.Duration(i*100)*time.Nanosecond
		packets[i].PortSrc = uint16(i & 0xFFFF)
		packets[i].PortDst = uint16((i >> 16) & 0xFFFF)
		packets[i].Reset()
		buffer[i] = &packets[i]
	}
	flowGenerator, _, _, _ := flowGeneratorInit(b.N, false)

	b.ResetTimer()
	flowGenerator.processPackets(buffer)

	b.Logf("map size=%d, totalFlow=%d, drop_by_capacity=%d, drop_before_window=%d, drop_after_window=%d",
		flowGenerator.flowMap.size, flowGenerator.flowMap.totalFlow, flowGenerator.flowMap.counter.DropByCapacity,
		flowGenerator.flowMap.counter.DropBeforeWindow, flowGenerator.flowMap.counter.DropAfterWindow)
}

func BenchmarkFlowMapWithTenPacketsFlowFlood(b *testing.B) {
	N := (b.N + 9) / 10 * 10
	packets := make([]MetaPacket, N)
	buffer := make([]interface{}, N)
	packetTemplate := getDefaultPacket()
	for i := 0; i < N; i += 10 { // 10Mpps, 1Mfps
		portSrc := uint16(i & 0xFFFF)
		portDst := uint16((i >> 16) & 0xFFFF)

		packets[i] = *packetTemplate
		packets[i].Timestamp = packetTemplate.Timestamp + time.Duration(i*100)*time.Nanosecond
		packets[i].PortSrc = portSrc
		packets[i].PortDst = portDst
		packets[i].Reset()
		buffer[i] = &packets[i]

		j := i + 1
		packets[j] = *packetTemplate
		reversePacket(&packets[j])
		packets[j].Timestamp = packetTemplate.Timestamp + time.Duration(j*100)*time.Nanosecond
		packets[j].PortSrc = portDst
		packets[j].PortDst = portSrc
		packets[j].TcpData.Flags = TCP_SYN | TCP_ACK
		packets[j].Reset()
		buffer[j] = &packets[j]

		for k := 2; k < 10; k++ {
			j = i + k
			packets[j] = *packetTemplate
			packets[j].Timestamp = packetTemplate.Timestamp + time.Duration(j*100)*time.Nanosecond
			packets[j].PortSrc = portSrc
			packets[j].PortDst = portDst
			packets[j].TcpData.Flags = TCP_ACK
			packets[j].Reset()
			buffer[j] = &packets[j]
		}
	}
	flowGenerator, _, _, _ := flowGeneratorInit(N, false)

	b.ResetTimer()
	flowGenerator.processPackets(buffer)

	b.Logf("b.N=%d map size=%d, width=%d, total=%d, drop_by_capacity=%d, drop_before_window=%d, drop_after_window=%d",
		b.N, flowGenerator.flowMap.size, flowGenerator.flowMap.width,
		flowGenerator.flowMap.totalFlow, flowGenerator.flowMap.counter.DropByCapacity,
		flowGenerator.flowMap.counter.DropBeforeWindow, flowGenerator.flowMap.counter.DropAfterWindow)
}
