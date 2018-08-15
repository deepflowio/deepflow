package flowgen

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"

	"gitlab.x.lan/yunshan/droplet/handler"
)

const DEFAULT_QUEUE_LEN = 200
const DEFAULT_INTERVAL_SEC_HIGH = 60
const DEFAULT_INTERVAL_SEC_LOW = 10
const DEFAULT_DURATION_MSEC = time.Millisecond * 123
const DEFAULT_PKT_LEN = 128

func getDefaultPacket() *handler.MetaPacketHeader {
	packet := &handler.MetaPacketHeader{}
	packet.MacSrc, _ = net.ParseMAC("12:34:56:78:9A:BC")
	packet.MacDst, _ = net.ParseMAC("21:43:65:87:A9:CB")
	packet.PacketLen = DEFAULT_PKT_LEN
	packet.Proto = 6
	packet.IpSrc = net.ParseIP("8.8.8.8")
	packet.IpDst = net.ParseIP("114.114.114.114")
	packet.PortSrc = 12345
	packet.PortDst = 22
	packet.InPort = 65533
	packet.Exporter = net.ParseIP("192.168.1.1")
	packet.TcpData.Flags = TCP_SYN
	packet.Timestamp = time.Duration(time.Now().UnixNano())
	packet.EndPointData = &EndpointData{
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
		},
	}

	return packet
}

func reversePacket(packet *handler.MetaPacketHeader) {
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
	if len(flowGenerator.fastPath.hashMap) != int(HASH_MAP_SIZE) {
		t.Errorf("flowGenerator.fastPath.hashMap len is %d, expect %d", len(flowGenerator.fastPath.hashMap), HASH_MAP_SIZE)
	}
}

func TestHandleSynRst(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	packet0 := getDefaultPacket()
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	go flowGenerator.handle()

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
	t.Logf("\n" + TaggedFlowString(taggedFlow))
}

func TestHandleSynFin(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK | TCP_FIN
	metaPacketHeaderInQueue.(Queue).Put(packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_PSH
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	go flowGenerator.handle()

	packet2 := getDefaultPacket()
	packet2.TcpData.Flags = TCP_SYN | TCP_ACK | TCP_FIN
	packet2.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet2)
	metaPacketHeaderInQueue.(Queue).Put(packet2)

	var taggedFlow *TaggedFlow
	taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow == nil {
		t.Error("flow is nil")
	} else {
		if taggedFlow.CloseType != CLOSE_TYPE_FIN {
			t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FIN)
		}
		if taggedFlow.TCPFlags0 != TCP_SYN|TCP_ACK|TCP_FIN|TCP_PSH ||
			taggedFlow.TCPFlags1 != TCP_SYN|TCP_ACK|TCP_FIN {
			t.Errorf("taggedFlow.TCPFlags0 is %d, expect %d", taggedFlow.TCPFlags0, TCP_SYN|TCP_ACK|TCP_FIN)
			t.Errorf("taggedFlow.TCPFlags1 is %d, expect %d", taggedFlow.TCPFlags1, TCP_SYN|TCP_ACK|TCP_FIN)
		}
		t.Logf("\n" + TaggedFlowString(taggedFlow))
	}
}

func TestHandleMultiPacket(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	var waitGroup sync.WaitGroup
	var packet *handler.MetaPacketHeader
	var taggedFlow *TaggedFlow
	num := DEFAULT_QUEUE_LEN / 2

	go flowGenerator.handle()

	// direct 0
	for i := 0; i < num; i++ {
		packet = getDefaultPacket()
		packet.TcpData.Flags = TCP_SYN
		packet.PortDst = uint16(i)
		metaPacketHeaderInQueue.(Queue).Put(packet)
	}

	waitGroup.Add(1)
	go func() {
		for flowGenerator.stats.CurrNumFlows != uint64(num) {
			continue
		}
		t.Logf("flowGenerator.stats.CurrNumFlows is %d, expect %d", flowGenerator.stats.CurrNumFlows, num)
		waitGroup.Done()
	}()
	// to wait for handler finish all packets
	waitGroup.Wait()

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
		if taggedFlow == nil {
			t.Errorf("taggedFlow is nil at i=%d", i)
			break
		} else if taggedFlow.TotalPacketCount0 != 1 ||
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
	flowExtra, _ := flowGenerator.initFlow(packet, flowKey)
	taggedFlow := flowExtra.taggedFlow

	if taggedFlow.FlowID == 0 {
		t.Error("taggedFlow.FlowID is 0 with an active flow")
	}
	if taggedFlow.TotalByteCount0 != uint64(packet.PacketLen) {
		t.Errorf("taggedFlow.TotalByteCount0 is %d, PacketLen is %d", taggedFlow.TotalByteCount0, packet.PacketLen)
	}

	if strings.Compare(taggedFlow.MACSrc.String(), packet.MacSrc.String()) != 0 ||
		strings.Compare(taggedFlow.MACDst.String(), packet.MacDst.String()) != 0 {
		t.Errorf("taggedFlow.MacSrc is %s, packet.MacSrc is %s", taggedFlow.MACSrc.String(), packet.MacSrc.String())
		t.Errorf("taggedFlow.MacDst is %s, packet.MacDst is %s", taggedFlow.MACDst.String(), packet.MacDst.String())
	}
	if strings.Compare(taggedFlow.IPSrc.String(), packet.IpSrc.String()) != 0 ||
		strings.Compare(taggedFlow.IPDst.String(), packet.IpDst.String()) != 0 {
		t.Errorf("taggedFlow.IpSrc is %s, packet.IpSrc is %s", taggedFlow.IPSrc.String(), packet.IpSrc.String())
		t.Errorf("taggedFlow.IpDst is %s, packet.IpDst is %s", taggedFlow.IPDst.String(), packet.IpDst.String())
	}
	if flowKey.Proto != packet.Proto {
		t.Errorf("flowKey.Proto is %d, packet.Proto is %d", taggedFlow.Proto, packet.Proto)
	}
	if taggedFlow.PortSrc != packet.PortSrc || taggedFlow.PortDst != packet.PortDst {
		t.Errorf("taggedFlow.PortSrc is %d, packet.PortSrc is %d", taggedFlow.PortSrc, packet.PortSrc)
		t.Errorf("taggedFlow.PortDst is %d, packet.PortDst is %d", taggedFlow.PortDst, packet.PortDst)
	}
}

func TestPlatformData(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	SetTimeout(TimeoutConfig{0, 1800, 30, 30, 5, 0})
	flowGenerator.minLoopIntervalSec = 0
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet1 := getDefaultPacket()
	//packet1.TcpData.Flags = TCP_RST
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(Queue).Put(packet1)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_HALF_OPEN {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_OPEN)
	}
	if taggedFlow.EpcID0 != -1 || taggedFlow.L3EpcID0 != -1 {
		t.Errorf("taggedFlow.EpcID0 is %d, expect -1", taggedFlow.EpcID0)
		t.Errorf("taggedFlow.L3EpcID0 is %d, expect -1", taggedFlow.L3EpcID0)
	}
	if taggedFlow.Host.Int() != 0x01010101 {
		t.Errorf("taggedFlow.Host is %d, expect %d", taggedFlow.Host.Int(), 0x01010101)
	}
	t.Logf("\n" + TaggedFlowString(taggedFlow))
}

func TestTCPStateMachine(t *testing.T) {
	flowExtra := &FlowExtra{}
	taggedFlow := &TaggedFlow{}
	flowExtra.taggedFlow = taggedFlow
	var packetFlags uint8

	taggedFlow.CloseType = CLOSE_TYPE_UNKNOWN
	flowExtra.flowState = FLOW_STATE_OPENING

	// test handshake
	taggedFlow.TCPFlags0 = TCP_SYN | TCP_ACK
	flowExtra.timeoutSec = TIMEOUT_OPENING
	packetFlags = TCP_SYN | TCP_ACK
	flowExtra.updateTCPStateMachine(packetFlags, true)
	flowExtra.calcCloseType()
	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT ||
		flowExtra.flowState != FLOW_STATE_ESTABLISHED {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
		t.Errorf("flowExtra.FlowState is %d, expecct %d", flowExtra.flowState, FLOW_STATE_ESTABLISHED)
	}

	// test fin close
	taggedFlow.TCPFlags0 = TCP_FIN | TCP_ACK | TCP_SYN
	flowExtra.timeoutSec = TIMEOUT_CLOSING
	flowExtra.flowState = FLOW_STATE_CLOSING
	packetFlags = TCP_FIN | TCP_ACK
	flowExtra.updateTCPStateMachine(packetFlags, true)
	flowExtra.calcCloseType()
	if taggedFlow.CloseType != CLOSE_TYPE_FIN ||
		flowExtra.flowState != FLOW_STATE_CLOSED {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FIN)
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSING)
	}

	// test rst close
	taggedFlow.TCPFlags0 = TCP_SYN
	flowExtra.timeoutSec = TIMEOUT_OPENING
	flowExtra.flowState = FLOW_STATE_OPENING
	packetFlags = TCP_RST | TCP_ACK | TCP_PSH
	flowExtra.updateTCPStateMachine(packetFlags, true)
	flowExtra.calcCloseType()
	if taggedFlow.CloseType != CLOSE_TYPE_RST ||
		flowExtra.flowState != FLOW_STATE_CLOSED {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_RST)
		t.Errorf("flowExtra.FlowState is %d, expect %d", flowExtra.flowState, FLOW_STATE_CLOSED)
	}
}

func TestHandshakePerf(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	flowGenerator.forceReportIntervalSec = 0
	flowGenerator.minLoopIntervalSec = 1
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

	flowGenerator.Start()

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
	}
	t.Logf("\n" + TaggedFlowString(taggedFlow))
}

func TestTimeoutReport(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPacketHeaderInQueue := flowGenerator.metaPacketHeaderInQueue
	flowGenerator.minLoopIntervalSec = 0
	SetTimeout(TimeoutConfig{0, 1800, 30, 30, 5, 0})
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	packet := getDefaultPacket()
	metaPacketHeaderInQueue.(Queue).Put(packet)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)

	if taggedFlow.CloseType != CLOSE_TYPE_HALF_OPEN {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_HALF_OPEN)
	}
	t.Logf("\n" + TaggedFlowString(taggedFlow))
	if flowGenerator.stats.CurrNumFlows != 0 || flowGenerator.stats.TotalNumFlows != 1 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect 0", flowGenerator.stats.CurrNumFlows)
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect 1", flowGenerator.stats.TotalNumFlows)
	}
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

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_PSH
	metaPacketHeaderInQueue.(Queue).Put(packet1)

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
	t.Logf("\n" + TaggedFlowString(taggedFlow))
	if flowGenerator.stats.CurrNumFlows != 1 || flowGenerator.stats.TotalNumFlows != 1 {
		t.Errorf("flowGenerator.stats.CurrNumFlows is %d, expect 1", flowGenerator.stats.CurrNumFlows)
		t.Errorf("flowGenerator.stats.TotalNumFlows is %d, expect 1", flowGenerator.stats.TotalNumFlows)
	}
}
