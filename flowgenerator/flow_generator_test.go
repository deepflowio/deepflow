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

const DEFAULT_QUEUE_LEN = 200
const DEFAULT_INTERVAL_HIGH = 60 * time.Second
const DEFAULT_INTERVAL_LOW = 10 * time.Second
const DEFAULT_DURATION_MSEC = time.Millisecond * 10
const DEFAULT_PKT_LEN = 128

var testTimeoutConfig = TimeoutConfig{
	Opening:         time.Millisecond * 10,
	Established:     TIMEOUT_ESTABLISHED,
	Closing:         time.Millisecond * 10,
	EstablishedRst:  TIMEOUT_ESTABLISHED_RST,
	Exception:       time.Millisecond * 10,
	ClosedFin:       TIMEOUT_CLOSED_FIN,
	SingleDirection: time.Millisecond * 10,
}

func flowGeneratorInit() (*FlowGenerator, MultiQueueReader, QueueWriter) {
	flowGeneratorCount = 1
	innerTcpSMA = make([]*ServiceManager, flowGeneratorCount)
	innerUdpSMA = make([]*ServiceManager, flowGeneratorCount)
	for i := uint64(0); i < flowGeneratorCount; i++ {
		innerTcpSMA[i] = NewServiceManager(32 * 1024)
		innerUdpSMA[i] = NewServiceManager(32 * 1024)
	}
	forceReportInterval = time.Millisecond * 100
	flowCleanInterval = time.Millisecond * 100
	timeoutCleanerCount = 4
	hashMapSize = 1024 * 32
	reportTolerance = 4 * time.Second
	ignoreTorMac = false
	ignoreL2End = false
	portStatsInterval = time.Second
	portStatsSrcEndCount = 5
	innerFlowGeo = testFlowGeo
	SetTimeout(testTimeoutConfig)
	metaPacketHeaderInQueue := NewOverwriteQueues("metaPacketHeaderInQueue", 1, DEFAULT_QUEUE_LEN)
	flowOutQueue := NewOverwriteQueue("flowOutQueue", DEFAULT_QUEUE_LEN)
	manager := queue.NewManager()
	meteringAppQueues := manager.NewQueues("3-meta-packet-to-metering-app", 1024, 1, 1)
	return New(metaPacketHeaderInQueue, flowOutQueue, meteringAppQueues, 64*1024, 1024*1024, 0), metaPacketHeaderInQueue, flowOutQueue
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
				L2EpcId:  -1,
				L3EpcId:  1,
				GroupIds: make([]uint32, 0, 10),
				HostIp:   0x01010101,
			},
			DstInfo: &EndpointInfo{
				L2EpcId:  -1,
				L3EpcId:  0,
				GroupIds: make([]uint32, 0, 10),
				HostIp:   0x01010101,
			},
		},
		PolicyData: &PolicyData{ActionFlags: ACTION_GEO_POSITIONING},
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
	flowGenerator, _, _ := flowGeneratorInit()
	forceReportInterval = 60 * time.Second

	if forceReportInterval != DEFAULT_INTERVAL_HIGH {
		t.Errorf("flowGenerator.forceReportInterval is %d, expect %d",
			forceReportInterval, DEFAULT_INTERVAL_HIGH)
	}
	if len(flowGenerator.hashMap) != int(hashMapSize) {
		t.Errorf("flowGenerator.hashMap len is %d, expect %d", len(flowGenerator.hashMap), hashMapSize)
	}
}

func TestTunnelMatch(t *testing.T) {
	flowGenerator, _, _ := flowGeneratorInit()
	metaTunnelInfo := &TunnelInfo{Type: 1, Src: 0, Dst: 2, Id: 1}
	flowTunnelInfo := &TunnelInfo{Type: 1, Src: 1, Dst: 3, Id: 1}
	if ok := flowGenerator.TunnelMatch(metaTunnelInfo, flowTunnelInfo); ok {
		t.Errorf("flowGenerator.TunnelMatch return %t, expect false", ok)
	}
}

func TestHandleSynRst(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	forceReportInterval = 60 * time.Second

	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
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
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	forceReportInterval = 60 * time.Second

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

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
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
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet1 := getDefaultPacket()
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	flowGenerator.Start()

	expectEpcID0, expectL3EpcId := int32(-1), int32(1)
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
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
	flowGenerator, _, _ := flowGeneratorInit()
	flowExtra := &FlowExtra{}
	taggedFlow := &TaggedFlow{}
	flowExtra.taggedFlow = taggedFlow
	var packetFlags uint8

	taggedFlow.CloseType = CloseTypeUnknown
	flowExtra.flowState = FLOW_STATE_OPENING_1

	// test handshake
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_SYN
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
	taggedFlow.FlowMetricsPeerSrc.TCPFlags = TCP_FIN
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
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

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

	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeForcedReport {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeForcedReport)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestStartStop(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	flowGenerator.Start()

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	flowGenerator.Stop()

	go func() {
		for {
			flowOutQueue.(QueueReader).Get()
		}
	}()
	t.Logf("CurrNumFlows is %d", flowGenerator.stats.CurrNumFlows)
}

func TestReverseInNewCircle(t *testing.T) {
	flowGenerator, _, _ := flowGeneratorInit()

	policyData0 := new(PolicyData)
	policyData0.Merge([]AclAction{generateAclAction(10, ACTION_PACKET_COUNTING)}, nil, 10)
	packet0 := getDefaultPacket()
	packet0.PolicyData = policyData0

	policyData1 := new(PolicyData)
	policyData1.Merge([]AclAction{generateAclAction(11, ACTION_PACKET_COUNTING)}, nil, 11)
	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	reversePacket(packet1)
	packet1.PolicyData = policyData1

	flowExtra := flowGenerator.initFlow(packet0, packet0.Timestamp)
	flowExtra.circlePktGot = false
	flowGenerator.updateFlow(flowExtra, packet1, true)

	direction := flowExtra.taggedFlow.PolicyData.AclActions[0].GetDirections()
	aclid := flowExtra.taggedFlow.PolicyData.ACLID
	if direction != BACKWARD || aclid != 11 {
		t.Errorf("taggedFlow.PolicyData.AclActions[0].GetDirections() is %d, expect %d", direction, BACKWARD)
		t.Errorf("taggedFlow.PolicyData.GetACLID is %d, expect %d", aclid, 11)
		t.Errorf("\n%s", flowExtra.taggedFlow)
	}
}

func TestForceReport(t *testing.T) {
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)

	if taggedFlow.CloseType != CloseTypeForcedReport {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeForcedReport)
	}
	if flowGenerator.stats.CurrNumFlows != 1 || flowGenerator.stats.TotalNumFlows != 1 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect 1", flowGenerator.stats.CurrNumFlows)
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect 1", flowGenerator.stats.TotalNumFlows)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpShortFlow(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet := getDefaultPacket()
	packet.Protocol = layers.IPProtocolUDP
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeTimeout {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeTimeout)
	}
	if taggedFlow.Proto != layers.IPProtocolUDP {
		t.Errorf("taggedFlow.Proto is %d, expect %d", taggedFlow.Proto, layers.IPProtocolUDP)
	}
}

func TestTimeFixAndDuration(t *testing.T) {
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet0 := getDefaultPacket()
	packet0.Timestamp -= 60 * time.Second
	minArrTime := packet0.Timestamp
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += 55 * time.Second
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	packet2.Timestamp += 60 * time.Second
	recentTime := packet2.Timestamp
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	pivotalTime := taggedFlow.EndTime - taggedFlow.EndTime%forceReportInterval
	if taggedFlow.StartTime != pivotalTime {
		t.Errorf("taggedFlow.StartTime is %d, expect %d", taggedFlow.StartTime, pivotalTime)
	}
	duration := recentTime - minArrTime
	if taggedFlow.Duration < duration {
		t.Errorf("taggedFlow.Duration is %d, expect %d", taggedFlow.Duration, duration)
	}
}

func TestNonIpShortFlow(t *testing.T) {
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet := getDefaultPacket()
	packet.Protocol = 0
	packet.EthType = layers.EthernetTypeARP
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CloseTypeTimeout {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CloseTypeTimeout)
	}
	if taggedFlow.EthType != layers.EthernetTypeARP {
		t.Errorf("taggedFlow.EthType is %d, expect %d", taggedFlow.EthType, layers.EthernetTypeARP)
	}
}

func TestInPortEqualTor(t *testing.T) {
	flowGenerator, _, _ := flowGeneratorInit()
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	ignoreTorMac = true
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	packet0 := getDefaultPacket()
	packet0.InPort = 0x30000
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	dst, _ := net.ParseMAC("21:43:65:AA:AA:AA")
	packet1.MacDst = MacIntFromBytes(dst)
	packet1.InPort = 0x30000
	packet1.TcpData.Flags = TCP_RST
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if cnt := taggedFlow.FlowMetricsPeerDst.PacketCount; cnt != 1 {
		t.Errorf("taggedFlow.FlowMetricsPeerDst.PacketCount is %d, expect 1", cnt)
	}
}

func TestIgnoreL2End(t *testing.T) {
	ignoreL2End = false
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, time.Millisecond * 10})
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()

	packet0 := getDefaultPacket()
	packet0.InPort = 0x31234
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	dst, _ := net.ParseMAC("21:43:65:AA:AA:AA")
	packet1.MacDst = MacIntFromBytes(dst)
	packet1.InPort = 0x31234
	packet1.L2End0 = true
	packet1.L2End1 = false
	packet1.TcpData.Flags = TCP_RST
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if cnt := taggedFlow.FlowMetricsPeerDst.PacketCount; cnt != 1 {
		t.Errorf("taggedFlow.FlowMetricsPeerDst.PacketCount is %d, expect 1", cnt)
	}
}

func TestDoubleFinFromServer(t *testing.T) {
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, time.Millisecond * 10})
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	// SYN
	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)
	// SYN | ACK
	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)
	// ACK
	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_ACK
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet2)
	// FIN
	packet3 := getDefaultPacket()
	packet3.TcpData.Flags = TCP_FIN
	reversePacket(packet3)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet3)
	// FIN
	packet4 := &MetaPacket{}
	*packet4 = *packet3
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet4)

	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.Flow.CloseType != CloseTypeClientHalfClose { // CloseTypeClientHalfClose是服务端发送FIN,而客户端未发送FIN
		t.Errorf("taggedFlow.Flow.CloseType is %d, expect %d", taggedFlow.Flow.CloseType, CloseTypeClientHalfClose)
	}
}

func BenchmarkCleanHashMap(b *testing.B) {
	runtime.GOMAXPROCS(4)
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	flowGenerator, _, _ := flowGeneratorInit()
	flowCache := &FlowCache{capacity: b.N, flowList: NewListFlowExtra()}
	flowGenerator.hashMap[0] = flowCache
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		flowExtra, _, _ := flowGenerator.initTcpFlow(meta)
		flowGenerator.addFlow(flowCache, flowExtra)
		flowGenerator.cleanTimeoutHashMap(0, 1, 0)
	}
	b.Logf("b.N: %d, NonEmptyFlowCacheNum: %d", b.N, flowGenerator.stats.NonEmptyFlowCacheNum)
}

func BenchmarkShortFlowList(b *testing.B) {
	runtime.GOMAXPROCS(4)
	flowGenerator, _, _ := flowGeneratorInit()
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	processBuffer := make([]interface{}, b.N)
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		meta.IpSrc += uint32(i)
		meta.GenerateQueueHash()
		processBuffer[i] = meta
	}
	b.ResetTimer()
	flowGenerator.packetHandler.Add(1)
	flowGenerator.processPackets(processBuffer)
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
	flowGenerator, _, _ := flowGeneratorInit()
	SetTimeout(TimeoutConfig{0, 300 * time.Second, 0, 30 * time.Second, 5 * time.Second, 0, 0})
	processBuffer := make([]interface{}, b.N)
	for i := 0; i < b.N; i++ {
		meta := getDefaultPacket()
		meta.PortDst += uint16(i)
		meta.GenerateQueueHash()
		processBuffer[i] = meta
	}
	b.ResetTimer()
	flowGenerator.packetHandler.Add(1)
	flowGenerator.processPackets(processBuffer)
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
