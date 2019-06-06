package flowgenerator

import (
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func testSeqSegmentIsContinuous(left, right, node *SeqSegment, t *testing.T) {
	if left == nil || right == nil || node == nil || t == nil {
		return
	}

	ret := isContinuousSeqSegment(left, right, node)
	if ret == SEQ_NODE_DISCONTINUOUS {
		t.Logf("%s test faild\n", t.Name())
	}
}

func TestSeqSegmentIsContinuous(t *testing.T) {
	var left, right, node *SeqSegment

	//nil,{5,10}
	node = &SeqSegment{1, 4}
	left = nil
	right = &SeqSegment{5, 10}
	testSeqSegmentIsContinuous(left, right, node, t)

	//{51,5}, nil
	node = &SeqSegment{56, 4}
	left = &SeqSegment{51, 5}
	right = nil
	testSeqSegmentIsContinuous(left, right, node, t)

	//{31,10},{51,5}
	node = &SeqSegment{41, 10}
	left = &SeqSegment{31, 10}
	right = &SeqSegment{51, 5}
	testSeqSegmentIsContinuous(left, right, node, t)
}

func assert2(t *testing.T, input []interface{}, expected []interface{}, output []interface{}, line int) {
	if len(input) > 0 {
		t.Logf("input(payload:%v):\n", len(input))
	}

	if len(expected) != len(output) {
		t.Errorf("expected items no equal ot output items")
	}

	t.Log("output payload:", len(output))
	for i := 0; i < len(expected); i++ {
		f := reflect.ValueOf(expected[i]).MethodByName("String")
		if f.IsValid() {
			f.Call(nil)
		}

		if reflect.TypeOf(expected[i]) != reflect.TypeOf(output[i]) {
			t.Errorf("expected and output are the same Type, expected.type:%s, output.type:%s",
				reflect.TypeOf(expected[i]).Name(), reflect.TypeOf(output[i]).Name())
			break
		}
	}
}

func testMergeSeqListNode(peer *TcpSessionPeer, node *SeqSegment, position int) {
	switch position {
	case -1:
		peer.insertSeqListNode(*node, 0)
		peer.mergeSeqListNode(0)
	case 0:
		peer.insertSeqListNode(*node, len(peer.seqArray)/2)
		peer.mergeSeqListNode(len(peer.seqArray) / 2)
	case 1:
		peer.insertSeqListNode(*node, len(peer.seqArray))
		peer.mergeSeqListNode(len(peer.seqArray) - 2)
	default:
	}
}

func TestMergeSeqListNode(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var payload uint16
	var node *SeqSegment
	peer := &TcpSessionPeer{}

	// insert {100, 10}, {200,10}, ... , {(SEQ_LIST_MAX_LEN-1)*100, 10}
	for i := 1; i <= SEQ_LIST_MAX_LEN; i++ {
		tcpHeader = &MetaPacketTcpHeader{Seq: uint32(100 * i), Ack: 20}
		payload = 10
		peer.assertSeqNumber(tcpHeader, payload)
	}
	//t.Log(peer.String())

	// test case {10, 10}
	node = &SeqSegment{seqNumber: 10, length: 10}
	testMergeSeqListNode(peer, node, -1)
	// {10, 100}
	//t.Log(peer.String())

	// test case {320, 10}
	node = &SeqSegment{seqNumber: 320, length: 10}
	testMergeSeqListNode(peer, node, 0)
	// {10, 200}
	//t.Log(peer.String())

	// {SEQ_LIST_MAX_LEN*10+10, 10}
	node = &SeqSegment{seqNumber: uint32(SEQ_LIST_MAX_LEN*100 + 10), length: 10}
	testMergeSeqListNode(peer, node, 1)
	// {10,320}
	//t.Log(peer.String())
}

func TestTcpSessionPeerSeqNoAssert(t *testing.T) {
	testTcpSessionPeerSeqNoAssert(t)
}

func testTcpSessionPeerSeqNoAssert(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var payload uint16

	peer := &TcpSessionPeer{}

	// 测试例 payload == 0
	if flag := peer.assertSeqNumber(&MetaPacketTcpHeader{}, 0); flag != SEQ_NOT_CARE {
		t.Logf("result is %v, expected %v", flag, SEQ_NOT_CARE)
	}

	if flag := peer.assertSeqNumber(&MetaPacketTcpHeader{}, 1); flag != SEQ_NOT_CARE {
		t.Logf("result is %v, expected %v", flag, SEQ_NOT_CARE)
	}
	// {0, 1}

	// {10, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10, Ack: 20}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
	}
	//t.Log(peer.String())

	// {20, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 20}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
	}
	// {10,20}
	//t.Log(peer.String())

	// right.seqNo+right.payload >= node.seqNo+node.len
	// input test case {10, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_RETRANS {
		t.Logf("result is %v, expected %v", flag, SEQ_RETRANS)
	}
	// {10, 20}
	//t.Log(peer.String())

	// 测试例 else node.seqNo < right.seqNo+right.len
	// {40, 20}, 异常情况{10,21}, {29, 5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 40}
	payload = 20
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
	}
	// {10,20}, {40,20}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 21
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Logf("result is %v, expected %v", flag, SEQ_ERROR)
	}
	// {10,20}, {40,20}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 29}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Logf("result is %v, expected %v", flag, SEQ_ERROR)
	}
	// {10,20}, {40,20}
	//t.Log(peer.String())

	// {10,20}, {40,20}
	// 测试例 left.seqNo <= node.seqNo
	// 测试例 node.seqNo+node.payload <= left.seqNo+left.len
	// {10,20}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 20
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_RETRANS {
		t.Logf("result is %v, expected %v", flag, SEQ_RETRANS)
	}
	// {10,20}, {40,20}
	//t.Log(peer.String())

	// 测试例 node.seqNo > left.seqNo+left.payload && node.seqNo+node.payload < right.seqNo
	// {31,4}
	tcpHeader = &MetaPacketTcpHeader{Seq: 31}
	payload = 4
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
	}
	// {10,20}, {31,4}, {40,20}
	//t.Log(peer.String())

	// 测试例 else node.seqNo == left.seqNo+left.payload || node.seqNo+node.payload == right.seqNo
	// {30,1}, {35,2}, {39,1}/*异常情况{38, 7}, {10,28}, {35,5}*/
	tcpHeader = &MetaPacketTcpHeader{Seq: 30}
	payload = 1
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS_BOTH {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS_BOTH)
	}
	// {10,25}, {40,20}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 35}
	payload = 2
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
	}
	// {10,27}, {40,20}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 39}
	payload = 1
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
	}
	// {10,27}, {39,21}
	//t.Log(peer.String())

	// 异常情况{38, 7}, {10,28}, {35,5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 38}
	payload = 7
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Logf("result is %v, expected %v", flag, SEQ_ERROR)
	}
	// {10,27}, {39,21}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 28
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Logf("result is %v, expected %v", flag, SEQ_ERROR)
	}
	// {10,27}, {39,21}
	//t.Log(peer.String())

	tcpHeader = &MetaPacketTcpHeader{Seq: 35}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Logf("result is %v, expected %v", flag, SEQ_ERROR)
	}
	// {10,27}, {39,21}
	//t.Log(peer.String())

	// 测试例 else /*left.seqNo > node.seqNo*/
	// 测试例 left.seqNo == node.seqNo+node.len
	// {5,5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 5}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
	}
	// {5,32}, {39,21}
	//t.Log(peer.String())

	// {1,3}
	tcpHeader = &MetaPacketTcpHeader{Seq: 1}
	payload = 3
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Logf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
	}
	// {0,4}, {5,32}, {39,21}
	//t.Log(peer.String())

	expected := [3]SeqSegment{{0, 4}, {5, 32}, {39, 21}}
	for i, n := range expected {
		if n.seqNumber != peer.seqArray[i].seqNumber ||
			n.length != peer.seqArray[i].length {
			t.Logf("result: %v", peer.seqArray)
			t.Logf("expected: %v", expected)
			break
		}
	}
}

func TestReestablishFsm(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var packetHeader *MetaPacket

	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()
	perfCtrl := flowPerf.ctrlInfo
	//perfData := flowPerf.perfData
	client := &perfCtrl.tcpSession[0]
	server := &perfCtrl.tcpSession[1]

	// 1SYN -> 2SYN/ACK -> 1ACK -> 1ACK/LEN>0 -> 2ACK -> 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0
	// 1SYN
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3333, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, TCP_DIR_CLIENT, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 2SYN/ACK rttSyn1 = 1
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3334, PayloadLen: 0}
	flowPerf.update(server, client, packetHeader, TCP_DIR_SERVER, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 1ACK rttSyn0 = 10
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3344, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, TCP_DIR_CLIENT, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 1ACK/LEN>0 len=100
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3350, PayloadLen: 100}
	flowPerf.update(client, server, packetHeader, TCP_DIR_CLIENT, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 2ACK rtt1 = 4
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3354, PayloadLen: 0}
	flowPerf.update(server, client, packetHeader, TCP_DIR_SERVER, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 2ACK/LEN>0 len=500 art1 = 30
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3384, PayloadLen: 500}
	flowPerf.update(server, client, packetHeader, TCP_DIR_SERVER, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 1ACK rtt0 = 16
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3400, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, TCP_DIR_CLIENT, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 1ACK/LEN>0 len=200 art0 = 54
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3454, PayloadLen: 200}
	flowPerf.update(client, server, packetHeader, TCP_DIR_CLIENT, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)
}

func TestAcquireMetaFlowPerf(t *testing.T) {
	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()
	t.Log(flowPerf.ctrlInfo, flowPerf.perfData)
	t.Log(counter.counter)
}

func TestPreprocess(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var packetHeader *MetaPacket

	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()

	//  SYN组合
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK | TCP_PSH | TCP_URG}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 1000}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	//  ACK组合
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK /*| TCP_FIN | TCP_RST*/ | TCP_PSH | TCP_URG}
	packetHeader = &MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}
	/*
		//  SYN异常组合
		tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN | TCP_RST | TCP_FIN}
		packetHeader = &MetaPacket{TcpData: tcpHeader}
		if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
			t.Errorf("tcpflag:0x%04x, faild, result:%v\n", tcpHeader.Flags, ok)
		}

		//  FIN异常组合
		tcpHeader = &MetaPacketTcpHeader{Flags: TCP_FIN | TCP_PSH | TCP_URG}
		packetHeader = &MetaPacket{TcpData: tcpHeader}
		if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
			t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
		}
	*/

	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_RST}
	packetHeader = &MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_FIN}
	packetHeader = &MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}
}

// call Update 11 times
func testMetaFlowPerfUpdate(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var packetHeader *MetaPacket

	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()
	flowExtra := &FlowExtra{
		taggedFlow: &TaggedFlow{},
	}

	/*
	 * rttSyn1=1, rttSyn0=10: 1SYN -> 2SYN/ACK -> 1ACK ->
	 * *art1=4, not rtt: 1ACK/LEN>0 -> 2ACK/LEN>0 -> 2ACK ->
	 * rtt0=16: 2ACK/LEN>0 -> 1ACK ->
	 * art0=70: 1ACK/LEN>0 ->
	 * *rtt1=100: 2ACK ->
	 * *art1=106: 2ACK/LEN>0 ->
	 * 非连续: 1ACK(重复) -> 1ACK ->
	 * 非连续: 2ACK/LEN>0 -> 2ACK/LEN>0 -> 1ACK(确认前一个包) ->
	 */

	// 1SYN
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3333, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2SYN/ACK rttSyn1=1
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3334, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 1ACK rttSyn0=10
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3344, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 1ACK/LEN>0 len=100
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3350, PayloadLen: 100}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2ACK/LEN>0包，len=100 *art1=4
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3354, PayloadLen: 100}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK 测试连续ACK包, 对RTT计算的影响
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1212, Ack: 212}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3358, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK/LEN>0 len=500
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1212, Ack: 212}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3384, PayloadLen: 500}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 1ACK rtt0=16
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3400, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 1ACK/LEN>0 len=200 art0=70
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3454, PayloadLen: 200}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2ACK *rtt1=100
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3554, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK/LEN>0 len=300 *art1=106
	tcpHeader = &MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	packetHeader = &MetaPacket{TcpData: tcpHeader, Timestamp: 3560, PayloadLen: 300}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)
	if t != nil {
		expectedPeriodPerfStats := MetaPerfStats{
			art0Count: 1, art1Count: 0, rtt0Count: 1, rtt1Count: 0,
			art0Sum: 70, art1Sum: 0, rtt0Sum: 16, rtt1Sum: 0,
			rttSyn0: 0, rttSyn1: 0, retrans0: 0, retrans1: 0,
			retransSyn0: 0, retransSyn1: 0, pshUrgCount0: 0,
			pshUrgCount1: 0, zeroWinCount0: 3, zeroWinCount1: 5,
		}
		expectedFlowPerfStats := MetaPerfStats{
			art0Count: 1, art1Count: 0, rtt0Count: 2, rtt1Count: 1,
			art0Sum: 70, art1Sum: 0, rtt0Sum: 16, rtt1Sum: 0,
			rttSyn0: 10, rttSyn1: 1, retrans0: 0, retrans1: 0,
			retransSyn0: 0, retransSyn1: 0, pshUrgCount0: 0,
			pshUrgCount1: 0, zeroWinCount0: 3, zeroWinCount1: 5,
		}
		resultPeriodPerfStats := flowPerf.perfData.periodPerfStats
		resultFlowPerfStats := flowPerf.perfData.flowPerfStats
		if !reflect.DeepEqual(expectedPeriodPerfStats, resultPeriodPerfStats) ||
			!reflect.DeepEqual(expectedFlowPerfStats, resultFlowPerfStats) {
			t.Logf("result periodPerfStats: %#v", resultPeriodPerfStats)
			t.Logf("expected periodPerfStats: %#v", expectedPeriodPerfStats)
			t.Logf("result flowPerfStats: %#v", resultFlowPerfStats)
			t.Logf("expected flowPerfStats: %#v", expectedFlowPerfStats)
		}
	}
}

func TestMetaFlowPerfUpdate(t *testing.T) {
	testMetaFlowPerfUpdate(t)
}

func testReport(flowPerf *MetaFlowPerf, t *testing.T) {
	var report *TcpPerfStats
	var periodData, flowData *MetaPerfStats

	counter := NewFlowPerfCounter()
	periodData = &flowPerf.perfData.periodPerfStats
	flowData = &flowPerf.perfData.flowPerfStats
	periodData.art0Sum = 100
	flowData.art0Sum += periodData.art0Sum
	periodData.art0Count = 1
	flowData.art0Count += periodData.art0Count

	periodData.art1Sum = 300
	flowData.art1Sum += periodData.art1Sum
	periodData.art1Count = 1
	flowData.art1Count += periodData.art1Count

	report = Report(flowPerf, false, &counter)

	if t != nil {
		t.Logf("flowperf.perfData:%v\nreport:%v\n", flowPerf.perfData, report)
	}

	periodData = &flowPerf.perfData.periodPerfStats
	flowData = &flowPerf.perfData.flowPerfStats
	periodData.art0Sum = 200
	flowData.art0Sum += periodData.art0Sum
	periodData.art0Count = 1
	flowData.art0Count += periodData.art0Count
	periodData.rtt0Sum = 1000
	flowData.rtt0Sum += periodData.rtt0Sum
	periodData.rtt0Count = 1
	flowData.rtt0Count += periodData.rtt0Count
	report = Report(flowPerf, true, &counter)

	if t != nil {
		t.Logf("flowperf.perfData:%v\nreport:%v\n", flowPerf.perfData, report)
		t.Log(counter.counter)
	}
}

func TestReport(t *testing.T) {
	flowPerf := AcquireMetaFlowPerf()
	testReport(flowPerf, t)
}

func testFlowPerfError(info string) error {
	err := FlowPerfError{what: info}
	return err.returnError()
}

func TestFlowPerfError(t *testing.T) {
	if err := testFlowPerfError(""); err != nil {
		t.Errorf("FlowPerfError return: %s\n", err.Error())
	}
	if err := testFlowPerfError("test error.what is not empty\n"); err != nil {
		t.Logf("FlowPerfError return: %s", err.Error())
	}
}

func TestVariance(t *testing.T) {
	var perf *TcpPerfStats

	counter := NewFlowPerfCounter()
	p := AcquireMetaFlowPerf()
	header := &MetaPacket{
		PacketLen: 1000,
		Timestamp: 2000,
	}
	p.calcVarianceStats(header, 1)
	perf = Report(p, false, &counter)
	t.Log(p.perfData.packetVariance)
	t.Log(perf)

	header = &MetaPacket{
		PacketLen: 4000,
		Timestamp: 6000,
	}
	p.calcVarianceStats(header, 2)
	perf = Report(p, false, &counter)
	t.Log(p.perfData.packetVariance)
	t.Log(perf)

	header = &MetaPacket{
		PacketLen: 64,
		Timestamp: 3000000,
	}
	p.calcVarianceStats(header, 3)
	perf = Report(p, false, &counter)
	t.Log(p.perfData.packetVariance)
	t.Log(perf)
}

func BenchmarkUpdate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testMetaFlowPerfUpdate(nil)
	}
}

func BenchmarkReport(b *testing.B) {
	flowPerf := AcquireMetaFlowPerf()

	for i := 0; i < b.N; i++ {
		testReport(flowPerf, nil)
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AcquireMetaFlowPerf()
	}
}

// call assertSeqNumber 20 times
func benchTcpSessionPeerSeqNoAssert(isDesc bool) {
	var tcpHeader *MetaPacketTcpHeader
	var payload uint16

	peer := &TcpSessionPeer{}

	// insert 16 node
	if !isDesc {
		for i := 0; i < SEQ_LIST_MAX_LEN; i++ {
			tcpHeader = &MetaPacketTcpHeader{Seq: uint32(i*10 + i), Ack: 20}
			payload = 10
			peer.assertSeqNumber(tcpHeader, payload)
		}
	} else {
		for i := SEQ_LIST_MAX_LEN; i >= 0; i-- {
			tcpHeader = &MetaPacketTcpHeader{Seq: uint32(i*10 + i), Ack: 20}
			payload = 10
			peer.assertSeqNumber(tcpHeader, payload)
		}
	}

	// isErrorSeqSegment
	tcpHeader = &MetaPacketTcpHeader{Seq: uint32(SEQ_LIST_MAX_LEN * 10), Ack: 20}
	payload = 10
	peer.assertSeqNumber(tcpHeader, payload)

	// isRetransSeqSegment
	tcpHeader = &MetaPacketTcpHeader{Seq: 0, Ack: 20}
	payload = 10
	peer.assertSeqNumber(tcpHeader, payload)

	// insert 17th node(mergeSeqListNode)
	tcpHeader = &MetaPacketTcpHeader{Seq: 200, Ack: 20}
	payload = 10
	peer.assertSeqNumber(tcpHeader, payload)

	// isContinuousSeqSegment
	tcpHeader = &MetaPacketTcpHeader{Seq: 10, Ack: 20}
	payload = 1
	peer.assertSeqNumber(tcpHeader, payload)
}

func BenchmarkTcpSessionPeerSeqNoAssertDesc(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchTcpSessionPeerSeqNoAssert(true)
	}
}

func BenchmarkTcpSessionPeerSeqNoAssert(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchTcpSessionPeerSeqNoAssert(false)
	}
}
