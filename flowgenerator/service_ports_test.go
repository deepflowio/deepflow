package flowgenerator

import (
	"net"
	"sync"
	"testing"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const DEFAULT_IP_LEARN_CNT = 5

func TestServiceKey(t *testing.T) {
	epcId := int32(-1)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port1 := uint16(80)
	port2 := uint16(8080)
	key1 := genServiceKey(epcId, ip, port1)
	key2 := genServiceKey(epcId, ip, port2)
	if key1 == key2 {
		t.Errorf("key1 %d should not be equal to key2 %d", key1, key2)
	}
}

func TestServicePortStatus(t *testing.T) {
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(-1)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port1 := uint16(80)
	port2 := uint16(8080)
	// check default IANA port service
	if !serviceManager.getStatus(genServiceKey(epcId, ip, port1), port1) {
		t.Error("serviceManager.getStatus() return false, expect true")
	}
	// check disable port service
	serviceManager.disableStatus(genServiceKey(epcId, ip, port2))
	if serviceManager.getStatus(genServiceKey(epcId, ip, port2), port2) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
}

func TestPortLearnInvalid(t *testing.T) {
	portStatsInterval = 0
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(3)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port := uint16(8080)
	key := genServiceKey(epcId, ip, port)
	if serviceManager.getStatus(key, port) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	for i := 0; i < DEFAULT_IP_LEARN_CNT; i++ {
		serviceManager.hitStatus(key, uint32(i+1), time.Duration(i*100))
	}
	if serviceManager.getStatus(key, port) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	serviceManager.enableStatus(key)
	if serviceManager.getStatus(key, port) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
}

func TestHitPortStatus(t *testing.T) {
	portStatsInterval = time.Second
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(3)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port := uint16(8080)
	key := genServiceKey(epcId, ip, port)
	if serviceManager.getStatus(key, port) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	for i := 0; i < DEFAULT_IP_LEARN_CNT; i++ {
		serviceManager.hitStatus(key, uint32(i+1), time.Duration(i*100))
	}
	if !serviceManager.getStatus(key, port) {
		t.Error("serviceManager.getStatus() return false, expect true")
	}
}

func TestGoroutinesServicePortStatus(t *testing.T) {
	portStatsInterval = time.Second
	portStatsSrcEndCount = 1
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(3)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port1 := uint16(80)
	port2 := uint16(8080)
	var waitGroup sync.WaitGroup

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		serviceManager.hitStatus(genServiceKey(epcId, ip, port2), uint32(123), time.Duration(123))
		if !serviceManager.getStatus(genServiceKey(epcId, ip, port2), port2) {
			t.Error("serviceManager.getStatus() return false, expect true")
		}
	}()
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		serviceManager.disableStatus(genServiceKey(epcId, ip, port1))
		if !serviceManager.getStatus(genServiceKey(epcId, ip, port1), port1) {
			t.Error("serviceManager.getStatus() return false, expect true")
		}
	}()
	waitGroup.Wait()
}

func TestSynAckDstPortInIANA(t *testing.T) {
	// 首包为syn/ack包，且目的端口位于IANA服务列表
	// 首包: syn/ack 12345 -> 22 flow: 22 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	packet0.TcpData.Seq = 1111
	packet0.TcpData.Ack = 112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 111
	packet1.TcpData.Ack = 0
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestSynSrcPortInIANA(t *testing.T) {
	// 首包为syn包，且源端口位于IANA服务列表
	// 首包: syn: 22 -> 12345  flow: 12345 -> 22
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortSrc, packet0.PortDst = packet0.PortDst, packet0.PortSrc
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestSynPortNotInIANA(t *testing.T) {
	port1 := uint16(8080)
	port2 := uint16(12345)

	// 首包为syn包，源端口不在IANA服务列表中,且不在lruCache中
	// 首包: syn 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortSrc = port1
	packet0.PortDst = port2
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	packet1.PortSrc = port2
	packet1.PortDst = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)
	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestSynSrcPortEnable(t *testing.T) {
	port1 := uint16(8080)

	// 首包为syn包，源端口不在IANA服务列表中，但在lruCache中
	// 首包: syn 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortDst = packet0.PortSrc
	packet0.PortSrc = port1
	l3EpcId := packet0.EndpointData.SrcInfo.L3EpcId
	serviceKey := genServiceKey(l3EpcId, packet0.IpSrc, packet0.PortSrc)
	getTcpServiceManager(serviceKey).enableStatus(serviceKey)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	packet1.PortSrc = packet1.PortDst
	packet1.PortDst = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestTcpAckSrcPortEnable(t *testing.T) {
	port1 := uint16(8080)

	// 首包为Ack包，源端口不在IANA服务列表中，但在lruCache中
	// 首包: Ack: 12345 -> 8080 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	portStatsSrcEndCount = 1
	flowGenerator.Start()
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_ACK
	packet0.TcpData.Seq = 100
	packet0.TcpData.Ack = 200
	packet0.PortDst = port1
	l3EpcId := packet0.EndpointData.SrcInfo.L3EpcId
	serviceKey := genServiceKey(l3EpcId, packet0.IpSrc, packet0.PortSrc)
	getTcpServiceManager(serviceKey).enableStatus(serviceKey)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 200
	packet1.TcpData.Ack = 140
	packet1.PortSrc = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet1.PortSrc, packet1.PortDst
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpSrcPortInIANA(t *testing.T) {
	// 首包: 80 -> 8080 flow: 8080 -> 80
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	portStatsSrcEndCount = 1
	flowGenerator.Start()
	packet0 := getUdpDefaultPacket()
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpBothPortsInIANA(t *testing.T) {
	port1 := uint16(200)

	// 首包: 80 -> 200 flow: 200 -> 80
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	portStatsSrcEndCount = 1
	minForceReportTime = time.Millisecond * 10
	packet0 := getUdpDefaultPacket()
	packet0.PortDst = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.PortSrc = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
	}
}

func TestUdpBothPortsNotInIANA(t *testing.T) {
	port1 := uint16(12345)

	// 首包: 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	packet0 := getUdpDefaultPacket()
	packet0.PortSrc = packet0.PortDst
	packet0.PortDst = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.PortDst = port1
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
}

func TestUdpHitStatus(t *testing.T) {
	portStatsSrcEndCount = 5
	serverPort := uint16(9999)
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	for i := 0; i < 5; i++ {
		packet := getUdpDefaultPacket()
		packet.Timestamp = DEFAULT_DURATION_MSEC * time.Duration(i)
		packet.PortDst = serverPort
		packet.PortSrc = uint16(3000 + i)
		metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	}
	flowGenerator.Start()
	for i := 0; i < 5; i++ {
		taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
		if taggedFlow.PortDst != serverPort {
			t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, serverPort)
		}
	}
}
