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
	. "gitlab.x.lan/yunshan/droplet-libs/queue"

	"gitlab.x.lan/yunshan/droplet/handler"
)

const DEFAULT_QUEUE_LEN = 200
const DEFAULT_INTERVAL_SEC_HIGH = 60
const DEFAULT_INTERVAL_SEC_LOW = 10
const DEFAULT_DURATION_MSEC = 123
const DEFAULT_PKT_LEN = 128

func getDefaultPkt() *handler.MetaPktHdr {
	pkt := &handler.MetaPktHdr{}
	pkt.MacSrc, _ = net.ParseMAC("12:34:56:78:9A:BC")
	pkt.MacDst, _ = net.ParseMAC("21:43:65:87:A9:CB")
	pkt.PktLen = DEFAULT_PKT_LEN
	pkt.Proto = 6
	pkt.IpSrc = net.ParseIP("8.8.8.8")
	pkt.IpDst = net.ParseIP("114.114.114.114")
	pkt.PortSrc = 12345
	pkt.PortDst = 22
	pkt.InPort = 65533
	pkt.Exporter = net.ParseIP("192.168.1.1")
	pkt.TcpData.Flags = TCP_SYN
	pkt.Timestamp = time.Now().UnixNano() / int64(time.Microsecond)

	return pkt
}

func reversePkt(pkt *handler.MetaPktHdr) {
	pkt.MacSrc, pkt.MacDst = pkt.MacDst, pkt.MacSrc
	pkt.IpSrc, pkt.IpDst = pkt.IpDst, pkt.IpSrc
	pkt.PortSrc, pkt.PortDst = pkt.PortDst, pkt.PortSrc
}

func getDefaultFlowGenerator() *FlowGenerator {
	metaPktHdrInQueue := NewOverwriteQueue("metaPktHdrInQueue", DEFAULT_QUEUE_LEN)
	flowOutQueue := NewOverwriteQueue("flowOutQueue", DEFAULT_QUEUE_LEN)
	return New(metaPktHdrInQueue, flowOutQueue, DEFAULT_INTERVAL_SEC_HIGH)
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
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	pkt0 := getDefaultPkt()
	metaPktHdrInQueue.(Queue).Put(pkt0)

	go flowGenerator.handle()

	pkt1 := getDefaultPkt()
	pkt1.TcpData.Flags = TCP_RST
	pkt1.Timestamp += DEFAULT_DURATION_MSEC
	reversePkt(pkt1)
	metaPktHdrInQueue.(Queue).Put(pkt1)

	var taggedFlow *TaggedFlow
	taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow == nil {
		t.Error("flow is nil")
	} else {
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
}

func TestHandleSynFin(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	pkt0 := getDefaultPkt()
	pkt0.TcpData.Flags = TCP_SYN | TCP_ACK | TCP_FIN
	metaPktHdrInQueue.(Queue).Put(pkt0)

	pkt1 := getDefaultPkt()
	pkt1.TcpData.Flags = TCP_PSH
	metaPktHdrInQueue.(Queue).Put(pkt1)

	go flowGenerator.handle()

	pkt2 := getDefaultPkt()
	pkt2.TcpData.Flags = TCP_SYN | TCP_ACK | TCP_FIN
	pkt2.Timestamp += DEFAULT_DURATION_MSEC
	reversePkt(pkt2)
	metaPktHdrInQueue.(Queue).Put(pkt2)

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

func TestHandleMultiPkt(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue
	var waitGroup sync.WaitGroup
	var pkt *handler.MetaPktHdr
	var taggedFlow *TaggedFlow
	num := DEFAULT_QUEUE_LEN / 2

	go flowGenerator.handle()

	// direct 0
	for i := 0; i < num; i++ {
		pkt = getDefaultPkt()
		pkt.TcpData.Flags = TCP_SYN
		pkt.PortDst = uint16(i)
		metaPktHdrInQueue.(Queue).Put(pkt)
	}

	waitGroup.Add(1)
	go func() {
		for flowGenerator.stats.CurrNumFlows != uint64(num) {
			continue
		}
		t.Logf("flowGenerator.stats.CurrNumFlows is %d, expect %d", flowGenerator.stats.CurrNumFlows, num)
		waitGroup.Done()
	}()
	// to wait for handler finish all pkts
	waitGroup.Wait()

	// direct 1
	for i := 0; i < num; i++ {
		pkt = getDefaultPkt()
		pkt.TcpData.Flags = TCP_RST
		pkt.PortDst = uint16(i)
		reversePkt(pkt)
		metaPktHdrInQueue.(Queue).Put(pkt)
	}

	for i := 0; i < num; i++ {
		taggedFlow = flowOutQueue.(Queue).Get().(*TaggedFlow)
		if taggedFlow == nil {
			t.Errorf("taggedFlow is nil at i=%d", i)
			break
		} else if taggedFlow.TotalPktCnt0 != 1 ||
			taggedFlow.TotalPktCnt1 != 1 {
			t.Error("taggedFlow.TotalPktCnt0 and taggedFlow.TotalPktCnt1 are not 1")
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
	pkt := getDefaultPkt()
	flowKey := getFlowKey(pkt)
	flowExtra, _ := flowGenerator.initFlow(pkt, flowKey)
	taggedFlow := flowExtra.taggedFlow

	if taggedFlow.FlowID == 0 {
		t.Error("taggedFlow.FlowID is 0 with an active flow")
	}
	if taggedFlow.TotalByteCnt0 != uint64(pkt.PktLen) {
		t.Errorf("taggedFlow.TotalByteCnt0 is %d, PktLen is %d", taggedFlow.TotalByteCnt0, pkt.PktLen)
	}

	if strings.Compare(taggedFlow.MACSrc.String(), pkt.MacSrc.String()) != 0 ||
		strings.Compare(taggedFlow.MACDst.String(), pkt.MacDst.String()) != 0 {
		t.Errorf("taggedFlow.MacSrc is %s, pkt.MacSrc is %s", taggedFlow.MACSrc.String(), pkt.MacSrc.String())
		t.Errorf("taggedFlow.MacDst is %s, pkt.MacDst is %s", taggedFlow.MACDst.String(), pkt.MacDst.String())
	}
	if strings.Compare(taggedFlow.IPSrc.String(), pkt.IpSrc.String()) != 0 ||
		strings.Compare(taggedFlow.IPDst.String(), pkt.IpDst.String()) != 0 {
		t.Errorf("taggedFlow.IpSrc is %s, pkt.IpSrc is %s", taggedFlow.IPSrc.String(), pkt.IpSrc.String())
		t.Errorf("taggedFlow.IpDst is %s, pkt.IpDst is %s", taggedFlow.IPDst.String(), pkt.IpDst.String())
	}
	if flowKey.Proto != pkt.Proto {
		t.Errorf("flowKey.Proto is %d, pkt.Proto is %d", taggedFlow.Proto, pkt.Proto)
	}
	if taggedFlow.PortSrc != pkt.PortSrc || taggedFlow.PortDst != pkt.PortDst {
		t.Errorf("taggedFlow.PortSrc is %d, pkt.PortSrc is %d", taggedFlow.PortSrc, pkt.PortSrc)
		t.Errorf("taggedFlow.PortDst is %d, pkt.PortDst is %d", taggedFlow.PortDst, pkt.PortDst)
	}
}

func TestTCPStateMachine(t *testing.T) {
	flowExtra := &FlowExtra{}
	taggedFlow := &TaggedFlow{}
	flowExtra.taggedFlow = taggedFlow
	var pktFlags uint8

	taggedFlow.CloseType = CLOSE_TYPE_UNKNOWN
	flowExtra.flowState = FLOW_STATE_OPENING

	// test handshake
	taggedFlow.TCPFlags0 = TCP_SYN | TCP_ACK
	flowExtra.timeoutSec = TIMEOUT_OPENING
	pktFlags = TCP_SYN | TCP_ACK
	flowExtra.updateTCPStateMachine(pktFlags, true)
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
	pktFlags = TCP_FIN | TCP_ACK
	flowExtra.updateTCPStateMachine(pktFlags, true)
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
	pktFlags = TCP_RST | TCP_ACK | TCP_PSH
	flowExtra.updateTCPStateMachine(pktFlags, true)
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
	flowGenerator.forceReportIntervalSec = 15
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	pkt0 := getDefaultPkt()
	pkt0.TcpData.Flags = TCP_SYN
	pkt0.TcpData.Seq = 111
	pkt0.TcpData.Ack = 0
	metaPktHdrInQueue.(Queue).Put(pkt0)

	pkt1 := getDefaultPkt()
	pkt1.TcpData.Flags = TCP_SYN | TCP_ACK
	pkt1.Timestamp += DEFAULT_DURATION_MSEC
	reversePkt(pkt1)
	pkt1.TcpData.Seq = 1111
	pkt1.TcpData.Ack = 112
	metaPktHdrInQueue.(Queue).Put(pkt1)

	pkt2 := getDefaultPkt()
	pkt2.TcpData.Flags = TCP_ACK
	pkt2.Timestamp += DEFAULT_DURATION_MSEC * 2
	pkt2.TcpData.Seq = 112
	pkt2.TcpData.Ack = 1112
	metaPktHdrInQueue.(Queue).Put(pkt2)

	taggedFlow := flowOutQueue.(Queue).Get().(*TaggedFlow)
	if taggedFlow.CloseType != CLOSE_TYPE_FORCE_REPORT {
		t.Errorf("taggedFlow.CloseType is %d, expect %d", taggedFlow.CloseType, CLOSE_TYPE_FORCE_REPORT)
	}
	t.Logf("\n" + TaggedFlowString(taggedFlow))
}

func TestTimeoutReport(t *testing.T) {
	runtime.GOMAXPROCS(4)
	flowGenerator := getDefaultFlowGenerator()
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	pkt := getDefaultPkt()
	metaPktHdrInQueue.(Queue).Put(pkt)

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
	flowGenerator.forceReportIntervalSec = 10
	metaPktHdrInQueue := flowGenerator.metaPktHdrInQueue
	flowOutQueue := flowGenerator.flowOutQueue

	flowGenerator.Start()

	pkt0 := getDefaultPkt()
	pkt0.TcpData.Flags = TCP_SYN | TCP_ACK
	metaPktHdrInQueue.(Queue).Put(pkt0)

	pkt1 := getDefaultPkt()
	pkt1.TcpData.Flags = TCP_PSH
	metaPktHdrInQueue.(Queue).Put(pkt1)

	pkt2 := getDefaultPkt()
	pkt2.TcpData.Flags = TCP_SYN | TCP_ACK
	pkt2.Timestamp += DEFAULT_DURATION_MSEC
	reversePkt(pkt2)
	metaPktHdrInQueue.(Queue).Put(pkt2)

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
