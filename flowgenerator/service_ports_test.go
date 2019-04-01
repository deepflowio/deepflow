package flowgenerator

import (
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const DEFAULT_IP_LEARN_CNT = 5

func generateAclGidBitmap(groupType uint32, offset uint32, bitOffset uint32) AclGidBitmap {
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag()
	if groupType == GROUP_TYPE_SRC {
		aclGidBitmap = aclGidBitmap.SetSrcMapOffset(offset)
	} else {
		aclGidBitmap = aclGidBitmap.SetDstMapOffset(offset)
	}
	if bitOffset != math.MaxUint32 {
		if groupType == GROUP_TYPE_SRC {
			aclGidBitmap = aclGidBitmap.SetSrcMapBits(bitOffset)
		} else {
			aclGidBitmap = aclGidBitmap.SetDstMapBits(bitOffset)
		}
	}

	return aclGidBitmap
}

func generateEndpointAndPolicy(packet *MetaPacket, srcGroupId, dstGroupId uint32, action AclAction, aclId ACLID) {
	packet.EndpointData.SrcInfo.GroupIds = append(packet.EndpointData.SrcInfo.GroupIds, srcGroupId)
	packet.EndpointData.DstInfo.GroupIds = append(packet.EndpointData.DstInfo.GroupIds, dstGroupId)
	aclGidBitmap0 := generateAclGidBitmap(GROUP_TYPE_SRC, 0, 0)
	aclGidBitmap1 := generateAclGidBitmap(GROUP_TYPE_DST, 0, 0)
	policyData := new(PolicyData)
	if action.GetDirections() == BACKWARD {
		action = action.SetACLGID(ACLID(dstGroupId))
		aclGidBitmap0, aclGidBitmap1 = aclGidBitmap1, aclGidBitmap0
	} else {
		action = action.SetACLGID(ACLID(srcGroupId))
	}
	policyData.Merge([]AclAction{action}, nil, aclId)
	policyData.AclActions[0] = policyData.AclActions[0].SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	policyData.AclGidBitmaps = append(policyData.AclGidBitmaps, aclGidBitmap0, aclGidBitmap1)
	packet.PolicyData = policyData
}

func checkPolicyResult(expected, actual *PolicyData) bool {
	if !reflect.DeepEqual(expected, actual) {
		return false
	}
	return true
}

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
	if !serviceManager.getStatus(genServiceKey(epcId, ip, port1), port1, 0) {
		t.Error("serviceManager.getStatus() return false, expect true")
	}
	// check disable port service
	serviceManager.disableStatus(genServiceKey(epcId, ip, port2))
	if serviceManager.getStatus(genServiceKey(epcId, ip, port2), port2, 0) {
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
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	for i := 0; i < DEFAULT_IP_LEARN_CNT; i++ {
		serviceManager.hitStatus(key, uint32(i+1), time.Duration(i*100))
	}
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	serviceManager.enableStatus(key, time.Second)
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
}

func TestHitPortStatus(t *testing.T) {
	portStatsInterval = time.Second
	portStatsTimeout = 0
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(3)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port := uint16(8080)
	key := genServiceKey(epcId, ip, port)
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	for i := 0; i < DEFAULT_IP_LEARN_CNT; i++ {
		serviceManager.hitStatus(key, uint32(i+1), time.Duration(i*100))
	}
	if !serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return false, expect true")
	}
}

func TestCheckTimeout(t *testing.T) {
	portStatsSrcEndCount = DEFAULT_IP_LEARN_CNT
	portStatsInterval = time.Second
	portStatsTimeout = 5 * time.Second
	serviceManager := NewServiceManager(64 * 1024)
	epcId := int32(3)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port := uint16(8080)
	key := genServiceKey(epcId, ip, port)
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
	}
	for i := 0; i < DEFAULT_IP_LEARN_CNT; i++ {
		serviceManager.hitStatus(key, uint32(i+1), time.Duration(i*100))
	}
	if !serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return false, expect true")
	}
	serviceManager.hitStatus(key, 100, 2*portStatsTimeout)
	if serviceManager.getStatus(key, port, 0) {
		t.Error("serviceManager.getStatus() return true, expect false")
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
		if !serviceManager.getStatus(genServiceKey(epcId, ip, port2), port2, 0) {
			t.Error("serviceManager.getStatus() return false, expect true")
		}
	}()
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		serviceManager.disableStatus(genServiceKey(epcId, ip, port1))
		if !serviceManager.getStatus(genServiceKey(epcId, ip, port1), port1, 0) {
			t.Error("serviceManager.getStatus() return false, expect true")
		}
	}()
	waitGroup.Wait()
}

func TestFlowReverseGroupId0(t *testing.T) {
	// 首包为syn/ack包，源端口位于IANA服务列表
	// 首包: syn/ack 22 -> 12345 flow: 12345 -> 22
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(0), uint32(math.MaxUint32)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	packet0.TcpData.Seq = 1111
	packet0.TcpData.Ack = 112
	packet0.PortSrc, packet0.PortDst = packet0.PortDst, packet0.PortSrc
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 111
	packet1.TcpData.Ack = 0
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestSynAckDstPortInIANA(t *testing.T) {
	// 首包为syn/ack包，且目的端口位于IANA服务列表
	// 首包: syn/ack 12345 -> 22 flow: 22 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	packet0.TcpData.Seq = 1111
	packet0.TcpData.Ack = 112
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 111
	packet1.TcpData.Ack = 0
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestSynSrcPortInIANA(t *testing.T) {
	// 首包为syn包，且源端口位于IANA服务列表
	// 首包: syn: 22 -> 12345  flow: 12345 -> 22
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortSrc, packet0.PortDst = packet0.PortDst, packet0.PortSrc
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual: %s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected: %s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestSynPortNotInIANA(t *testing.T) {
	port1 := uint16(8080)
	port2 := uint16(12345)

	// 首包为syn包，源端口不在IANA服务列表中,且不在lruCache中
	// 首包: syn 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortSrc = port1
	packet0.PortDst = port2
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	packet1.PortSrc = port2
	packet1.PortDst = port1
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	expectSrcGroupId, expectDstGroupId := packet0.EndpointData.SrcInfo.GroupIds, packet0.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet0.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestSynSrcPortEnable(t *testing.T) {
	port1 := uint16(8080)

	// 首包为syn包，源端口不在IANA服务列表中，但在lruCache中
	// 首包: syn 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN
	packet0.TcpData.Seq = 111
	packet0.TcpData.Ack = 0
	packet0.PortDst = packet0.PortSrc
	packet0.PortSrc = port1
	l3EpcId := packet0.EndpointData.SrcInfo.L3EpcId
	serviceKey := genServiceKey(l3EpcId, packet0.IpSrc, packet0.PortSrc)
	getTcpServiceManager(serviceKey).enableStatus(serviceKey, packet0.Timestamp)
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN | TCP_ACK
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 1111
	packet1.TcpData.Ack = 112
	packet1.PortSrc = packet1.PortDst
	packet1.PortDst = port1
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	expectSrcGroupId, expectDstGroupId := packet0.EndpointData.SrcInfo.GroupIds, packet0.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet0.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestSynAckSrcPortEnable(t *testing.T) {
	port1 := uint16(8080)

	// 首包为Syn/Ack包，源端口不在IANA服务列表中，但在lruCache中
	// 首包: Syn/Ack: 12345 -> 8080 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	portStatsSrcEndCount = 1
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getDefaultPacket()
	packet0.TcpData.Flags = TCP_SYN | TCP_ACK
	packet0.TcpData.Seq = 100
	packet0.TcpData.Ack = 201
	packet0.PortDst = port1
	l3EpcId := packet0.EndpointData.SrcInfo.L3EpcId
	serviceKey := genServiceKey(l3EpcId, packet0.IpSrc, packet0.PortSrc)
	getTcpServiceManager(serviceKey).enableStatus(serviceKey, packet0.Timestamp)
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getDefaultPacket()
	packet1.TcpData.Flags = TCP_SYN
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.TcpData.Seq = 200
	packet1.TcpData.Ack = 140
	packet1.PortSrc = port1
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet1.PortSrc, packet1.PortDst
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestUdpSrcPortInIANA(t *testing.T) {
	// 首包: 80 -> 8080 flow: 8080 -> 80
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	portStatsSrcEndCount = 1
	flowGenerator.Start()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getUdpDefaultPacket()
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestUdpBothPortsInIANA(t *testing.T) {
	port1 := uint16(200)

	// 首包: 80 -> 200 flow: 200 -> 80
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	portStatsSrcEndCount = 1
	packet0 := getUdpDefaultPacket()
	packet0.PortDst = port1
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.PortSrc = port1
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortDst, packet0.PortSrc
	expectSrcGroupId, expectDstGroupId := packet1.EndpointData.SrcInfo.GroupIds, packet1.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet1.PolicyData
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestUdpBothPortsNotInIANA(t *testing.T) {
	port1 := uint16(12345)

	// 首包: 8080 -> 12345 flow: 8080 -> 12345
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	// 根据首包确定srcGroupId、dstGroupId
	srcGroupId, dstGroupId := uint32(10), uint32(20)
	packet0 := getUdpDefaultPacket()
	packet0.PortSrc = packet0.PortDst
	packet0.PortDst = port1
	action0 := generateAclAction(10, ACTION_PACKET_COUNTING|ACTION_FLOW_COUNTING)
	generateEndpointAndPolicy(packet0, srcGroupId, dstGroupId, action0, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet0)

	packet1 := getUdpDefaultPacket()
	packet1.Timestamp += DEFAULT_DURATION_MSEC
	reversePacket(packet1)
	packet1.PortDst = port1
	action1 := action0.SetDirections(BACKWARD)
	generateEndpointAndPolicy(packet1, dstGroupId, srcGroupId, action1, 10)
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet1)

	expectPortSrc, expectPortDst := packet0.PortSrc, packet0.PortDst
	expectSrcGroupId, expectDstGroupId := packet0.EndpointData.SrcInfo.GroupIds, packet0.EndpointData.DstInfo.GroupIds
	expectPolicyData := packet0.PolicyData
	flowGenerator.Start()
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != expectPortSrc || taggedFlow.PortDst != expectPortDst {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, expectPortSrc)
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, expectPortDst)
		t.Errorf("\n%s", taggedFlow)
	}
	if taggedFlow.Tag.GroupIDs0[0] != expectSrcGroupId[0] || taggedFlow.Tag.GroupIDs1[0] != expectDstGroupId[0] {
		t.Errorf("taggedFlow.Tag.GroupIDs0 is %d, expect %d", taggedFlow.Tag.GroupIDs0, expectSrcGroupId)
		t.Errorf("taggedFlow.Tag.GroupIDs1 is %d, expect %d", taggedFlow.Tag.GroupIDs1, expectDstGroupId)
		t.Errorf("\n%s", taggedFlow)
	}
	if !checkPolicyResult(expectPolicyData, taggedFlow.Tag.PolicyData) {
		t.Errorf("Actual:%s\n", taggedFlow.Tag.PolicyData)
		t.Errorf("Expected:%s\n", expectPolicyData)
		t.Errorf("%s\n", taggedFlow)
	}
}

func TestUdpHitStatus(t *testing.T) {
	portStatsInterval = time.Second
	portStatsSrcEndCount = 5
	serverPort := uint16(9999)
	flowGenerator, metaPacketHeaderInQueue, flowOutQueue := flowGeneratorInit()
	now := time.Duration(time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		packet := getUdpDefaultPacket()
		packet.Timestamp = now + DEFAULT_DURATION_MSEC*time.Duration(i)
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
	packet := getUdpDefaultPacket()
	reversePacket(packet)
	packet.PortSrc = serverPort
	packet.PortDst = 12345
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortDst != serverPort {
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, serverPort)
	}
}

func TestUdpPortTimeout(t *testing.T) {
	portStatsInterval = time.Second
	portStatsSrcEndCount = 5
	portStatsTimeout = 5 * time.Second
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

	packet := getUdpDefaultPacket()
	packet.Timestamp = 10*DEFAULT_DURATION_MSEC + portStatsTimeout
	packet.PortDst = serverPort
	packet.PortSrc = 4000
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	taggedFlow := flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortDst != serverPort {
		t.Errorf("taggedFlow.PortDst is %d, expect %d", taggedFlow.PortDst, serverPort)
	}

	packet = getUdpDefaultPacket()
	reversePacket(packet)
	packet.PortSrc = serverPort
	packet.PortDst = 12346
	metaPacketHeaderInQueue.(MultiQueueWriter).Put(0, packet)
	taggedFlow = flowOutQueue.(QueueReader).Get().(*TaggedFlow)
	if taggedFlow.PortSrc != serverPort {
		t.Errorf("taggedFlow.PortSrc is %d, expect %d", taggedFlow.PortSrc, serverPort)
	}
}
