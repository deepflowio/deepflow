package flowperf

import (
	"container/list"
	"fmt"
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"

	"gitlab.x.lan/yunshan/droplet/handler"
)

func testSeqSegmentIsContinuous(peer TcpSessionPeer, left, right, node *SeqSegment, t *testing.T) {
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

	peer := TcpSessionPeer{seqList: list.New()}
	l := peer.seqList
	node = &SeqSegment{}

	node = &SeqSegment{}
	e3 := l.PushBack(&SeqSegment{5, 10})
	e4 := l.PushBack(&SeqSegment{31, 10})
	e5 := l.PushBack(&SeqSegment{51, 5})

	//nil,{5,10}
	node = &SeqSegment{1, 4}
	left = nil
	right = e3.Value.(*SeqSegment)
	testSeqSegmentIsContinuous(peer, left, right, node, t)

	//{51,5}, nil
	node = &SeqSegment{56, 4}
	left = e5.Value.(*SeqSegment)
	right = nil
	testSeqSegmentIsContinuous(peer, left, right, node, t)

	//{31,10},{51,5}
	node = &SeqSegment{41, 10}
	left = e4.Value.(*SeqSegment)
	right = e5.Value.(*SeqSegment)
	testSeqSegmentIsContinuous(peer, left, right, node, t)
	t.Log(peer.String())
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
		peer.seqList.PushFront(node)
	case 0:
		peer.seqList.InsertAfter(node, peer.seqList.Front().Next())
	case 1:
		peer.seqList.PushBack(node)
	default:
	}

	peer.mergeSeqListNode()
}

func TestMergeSeqListNode(t *testing.T) {
	var tcpHeader *handler.MetaPacketTcpHeader
	var payload uint16
	var node *SeqSegment
	peer := &TcpSessionPeer{}

	// init list
	if peer.seqList == nil {
		peer.seqList = list.New()
	}

	// insert {100, 10}, {200,10}, ... , {(SEQ_LIST_MAX_LEN-1)*100, 10}
	for i := 1; i < SEQ_LIST_MAX_LEN; i++ {
		tcpHeader = &handler.MetaPacketTcpHeader{Seq: uint32(100 * i), Ack: 20}
		payload = 10
		peer.assertSeqNumber(tcpHeader, payload)
	}
	t.Log(peer.String())

	// test case {10, 10}
	node = &SeqSegment{seqNumber: 10, length: 10}
	testMergeSeqListNode(peer, node, -1)
	// {10, 100}
	t.Log(peer.String())

	// test case {320, 10}
	node = &SeqSegment{seqNumber: 320, length: 10}
	testMergeSeqListNode(peer, node, 0)
	// {10, 200}
	t.Log(peer.String())

	// {SEQ_LIST_MAX_LEN*10+10, 10}
	node = &SeqSegment{seqNumber: uint32(SEQ_LIST_MAX_LEN*10 + 10), length: 10}
	testMergeSeqListNode(peer, node, 1)
	// {10,320}
	t.Log(peer.String())
}

func TestTcpSessionPeerSeqNoAssert(t *testing.T) {
	var tcpHeader *handler.MetaPacketTcpHeader
	var payload uint16
	var l *list.List

	peer := &TcpSessionPeer{}

	// 测试例 payload == 0
	peer.assertSeqNumber(&handler.MetaPacketTcpHeader{}, 0)

	peer.assertSeqNumber(&handler.MetaPacketTcpHeader{}, 1)

	// init list
	if peer.seqList == nil {
		peer.seqList = list.New()
		l = peer.seqList
	}

	// list is empty, insert {10, 10}
	if l.Len() == 0 {
		tcpHeader = &handler.MetaPacketTcpHeader{Seq: 10, Ack: 20}
		payload = 10
		peer.assertSeqNumber(tcpHeader, payload)
	}

	// {20, 10}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 20}
	payload = 10
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}
	t.Log(peer.String())

	// right.seqNo+right.payload >= node.seqNo+node.len
	// input test case {10, 10}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 10}
	payload = 10
	peer.assertSeqNumber(tcpHeader, payload)
	// {10, 20}
	t.Log(peer.String())

	//	测试例 else node.seqNo < right.seqNo+right.len
	//  {40, 20}, 异常情况{10,21}, {29, 5}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 40}
	payload = 20
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 10}
	payload = 21
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 29}
	payload = 5
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	// {10,20}, {40,20}
	// 测试例 left.seqNo <= node.seqNo
	// 测试例 node.seqNo+node.payload <= left.seqNo+left.len
	// {10,20}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 10}
	payload = 20
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	// 测试例 node.seqNo > left.seqNo+left.payload && node.seqNo+node.payload < right.seqNo
	// {31,4}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 31}
	payload = 4
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,20}, {31,4}, {40,20}
	t.Log(peer.String())

	// 测试例 else node.seqNo == left.seqNo+left.payload || node.seqNo+node.payload == right.seqNo
	// {30,1}, {35,2}, {39,1}/*异常情况{38, 7}, {10,28}, {35,5}*/
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 30}
	payload = 1
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,25}, {40,20}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 35}
	payload = 2
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,27}, {40,20}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 39}
	payload = 1
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	// 异常情况{38, 7}, {10,28}, {35,5}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 38}
	payload = 7
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 10}
	payload = 28
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 35}
	payload = 5
	peer.assertSeqNumber(tcpHeader, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	// 测试例 else /*left.seqNo > node.seqNo*/
	// 测试例 left.seqNo == node.seqNo+node.len
	// {5,5}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 5}
	payload = 5
	peer.assertSeqNumber(tcpHeader, payload)
	// {5,33}, {39,21}
	t.Log(peer.String())

	// {1,3}
	tcpHeader = &handler.MetaPacketTcpHeader{Seq: 1}
	payload = 3
	peer.assertSeqNumber(tcpHeader, payload)
	// {1,3}, {5,33}, {39,21}
	t.Log(peer.String())
}

func TestFlowPerfCtrlInfoFirstPacket(t *testing.T) {
	client := TcpSessionPeer{seqList: list.New()}
	server := TcpSessionPeer{seqList: list.New()}
	perfCtrl := &FlowPerfCtrlInfo{ /*isFirstPacket: true, */ tcpSession: TcpConnSession{client, server}}

	input, expected := make([]interface{}, 2), make([]interface{}, 2)
	// output := expected //output， expected引用相同的底层，相当于指针指向同一地址
	output := make([]interface{}, 2)

	// SYN
	tcpHeader := handler.MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 123, Ack: 321}
	packetHeader := &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 5678, PayloadLen: 0}
	perfCtrl.firstPacket(packetHeader)
	input[0] = tcpHeader
	input[1] = packetHeader
	l0 := list.New()
	l0.PushFront(&SeqSegment{123, 1})
	expected[0] = TcpSessionPeer{seq: 123, payloadLen: 0, timestamp: 5678, tcpState: TCP_STATE_SYN_SENT,
		seqList: l0}
	l1 := list.New()
	expected[1] = TcpSessionPeer{tcpState: TCP_STATE_LISTEN, seqList: l1}
	output[0] = perfCtrl.tcpSession[0]
	output[1] = perfCtrl.tcpSession[1]

	// SYN/ACK
	client = TcpSessionPeer{seqList: list.New()}
	server = TcpSessionPeer{seqList: list.New()}
	perfCtrl = &FlowPerfCtrlInfo{ /*isFirstPacket: true, */ tcpSession: TcpConnSession{client, server}}
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 124, Ack: 421}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 6678, PayloadLen: 0}
	perfCtrl.firstPacket(packetHeader)
	input[0] = tcpHeader
	input[1] = packetHeader
	l0 = list.New()
	l0.PushFront(&SeqSegment{124, 1})
	exp := TcpSessionPeer{seq: 124, payloadLen: 0, timestamp: 6678, tcpState: TCP_STATE_SYN_RECV,
		seqList: l0}
	l1 = list.New()
	expected[0] = exp
	expected[1] = TcpSessionPeer{tcpState: TCP_STATE_SYN_SENT, seqList: l1}
	output[0] = perfCtrl.tcpSession[0]
	output[1] = perfCtrl.tcpSession[1]

	// ACK
	client = TcpSessionPeer{seqList: list.New()}
	server = TcpSessionPeer{seqList: list.New()}
	perfCtrl = &FlowPerfCtrlInfo{ /*isFirstPacket: true, */ tcpSession: TcpConnSession{client, server}}
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 125, Ack: 521}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 7678, PayloadLen: 0}
	perfCtrl.firstPacket(packetHeader)
	input[0] = tcpHeader
	input[1] = packetHeader
	l0 = list.New()
	expected[0] = TcpSessionPeer{seq: 125, payloadLen: 0, timestamp: 7678, tcpState: TCP_STATE_ESTABLISHED,
		seqList: l0}
	l1 = list.New()
	expected[1] = TcpSessionPeer{tcpState: TCP_STATE_ESTABLISHED, seqList: l1}
	output[0] = perfCtrl.tcpSession[0]
	output[1] = perfCtrl.tcpSession[1]
}

func TestReestablishFsm(t *testing.T) {
	var tcpHeader handler.MetaPacketTcpHeader
	var packetHeader *handler.MetaPacket
	var direction bool

	flowPerf := NewMetaFlowPerf()
	perfCtrl := flowPerf.ctrlInfo
	perfData := flowPerf.perfData
	client := &perfCtrl.tcpSession[0]
	server := &perfCtrl.tcpSession[1]
	// 1SYN -> 2SYN/ACK -> 1ACK -> 1ACK/LEN>0 -> 2ACK -> 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0
	// 1SYN
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3333, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2SYN/ACK rttSyn1
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3334, PayloadLen: 0}
	flowPerf.reestablishFsm(server, client, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK rttSyn0
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3344, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK/LEN>0 len=100
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3350, PayloadLen: 100}
	flowPerf.reestablishFsm(client, server, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2ACK rttS1
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3354, PayloadLen: 0}
	flowPerf.reestablishFsm(server, client, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2ACK/LEN>0 len=500 art
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3384, PayloadLen: 500}
	flowPerf.reestablishFsm(server, client, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK rttS0
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3400, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK/LEN>0 len=200
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3454, PayloadLen: 200}

	flowPerf.reestablishFsm(client, server, packetHeader, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
}

func TestNewMetaFlowPerf(t *testing.T) {
	flowPerf := NewMetaFlowPerf()
	t.Log(flowPerf.ctrlInfo, flowPerf.perfData, /*, flowPerf.counter*/
		flowPerf.ctrlInfo.tcpSession[0].seqList.PushFront(&SeqSegment{111, 11}))
	/*
		flow_perf_quantify_test.go:346: &{[{0xc42001f0e0 0 0 0 0 0 0 false false} {0xc42001f110 0 0 0 0 0 0 false false}]}
		reportPerfStats:{
			SynRetransCount0: 0, SynRetransCount1: 0;
			ARTAvg: 0, RTTSyn: 0, RTT: 0, RTTAvg: 0;
			RetransCount0: 0, RetransCount1: 0, TotalRetransCount: 0;
			ZeroWinCount0: 0; ZeroWinCount1: 0, TotalZeroWinCount: 0;
			SlowStartCount0: 0, SlowStartCount1: 0, TotalSlowStartCount: 0;
			PshUrgCount0: 0, PshUrgCount1: 0, TotalPshUrgCount: 0
		},
		periodPerfStats:{
			artSum: 0, artCount: 0; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 0, rtt0Count: 0; rtt1Sum: 0, rtt1Count: 0;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCount0: 0, pshUrgCount1: 0; zeroWinCount0: 0, zeroWinCount1: 0
		},
		flowPerfStats:{
			artSum: 0, artCount: 0; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 0, rtt0Count: 0; rtt1Sum: 0, rtt1Count: 0;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCount0: 0, pshUrgCount1: 0; zeroWinCount0: 0, zeroWinCount1: 0
		} &{0xc42001f0e0 0xc42001f0e0 0xc42001f0e0 0xc421228a30}
	*/
}

func TestPreprocess(t *testing.T) {
	var tcpHeader handler.MetaPacketTcpHeader
	var packetHeader *handler.MetaPacket

	flowPerf := NewMetaFlowPerf()

	//  SYN组合
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK | TCP_PSH | TCP_URG}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 1000}
	if ok := flowPerf.preprocess(packetHeader); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	//  ACK组合
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK /*| TCP_FIN | TCP_RST*/ | TCP_PSH | TCP_URG}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}
	/*
		//  SYN异常组合
		tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN | TCP_RST | TCP_FIN}
		packetHeader = &handler.MetaPacket{TcpData: tcpHeader}
		if ok := flowPerf.preprocess(packetHeader); ok != false {
			t.Errorf("tcpflag:0x%04x, faild, result:%v\n", tcpHeader.Flags, ok)
		}

		//  FIN异常组合
		tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_FIN | TCP_PSH | TCP_URG}
		packetHeader = &handler.MetaPacket{TcpData: tcpHeader}
		if ok := flowPerf.preprocess(packetHeader); ok != false {
			t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
		}
	*/

	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_RST}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_FIN}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader}
	if ok := flowPerf.preprocess(packetHeader); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}
}

func testMetaFlowPerfUpdate() {
	var tcpHeader handler.MetaPacketTcpHeader
	var packetHeader *handler.MetaPacket
	var direction bool

	flowPerf := NewMetaFlowPerf()

	/*
	 * rtt_syn: 1SYN -> 2SYN/ACK -> 1ACK ->
	 * 非连续: 1ACK/LEN>0 -> 2ACK/LEN>0 -> 2ACK ->
	 * rtt0: 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0 ->
	 * rtt1: 2ACK ->
	 * art: 2ACK/LEN>0 ->
	 * 非连续: 1ACK(重复) -> 1ACK ->
	 * 非连续: 2ACK/LEN>0 -> 2ACK/LEN>0 -> 1ACK(确认前一个包) ->
	 */

	// 1SYN
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3333, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 2SYN/ACK rttSyn1=1
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3334, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 1ACK rttSyn0=10
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3344, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 1ACK/LEN>0 len=100
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3350, PayloadLen: 100}
	flowPerf.Update(packetHeader, direction)

	// 测试连续2ACK/LEN>0包，len=100, 对RTT计算的影响
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3354, PayloadLen: 100}
	flowPerf.Update(packetHeader, direction)

	// 2ACK
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1212, Ack: 212}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3358, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 2ACK/LEN>0 len=500
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1212, Ack: 212}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3384, PayloadLen: 500}
	flowPerf.Update(packetHeader, direction)

	// 1ACK rtt0=16
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3400, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 1ACK/LEN>0 len=200
	direction = false
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3454, PayloadLen: 200}
	flowPerf.Update(packetHeader, direction)

	// 2ACK rtt1=100
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3554, PayloadLen: 0}
	flowPerf.Update(packetHeader, direction)

	// 2ACK/LEN>0 len=300 art=6
	direction = true
	tcpHeader = handler.MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	packetHeader = &handler.MetaPacket{TcpData: tcpHeader, Timestamp: 3560, PayloadLen: 300}
	flowPerf.Update(packetHeader, direction)

}

func TestMetaFlowPerfUpdate(t *testing.T) {
	testMetaFlowPerfUpdate()
	/*
		reportPerfStats:{
			SynRetransCount0: 0, SynRetransCount1: 0;
			ARTAvg: 0, RTTSyn: 0, RTT: 0, RTTAvg: 0;
			RetransCount0: 0, RetransCount1: 0, TotalRetransCount: 0;
			ZeroWinCount0: 0; ZeroWinCount1: 0, TotalZeroWinCount: 0;
			SlowStartCount0: 0, SlowStartCount1: 0, TotalSlowStartCount: 0;
			PshUrgCount0: 0, PshUrgCount1: 0, TotalPshUrgCount: 0
		},
		periodPerfStats:{
			artSum: 6, artCount: 1; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 16, rtt0Count: 1; rtt1Sum: 100, rtt1Count: 1;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCount0: 0, pshUrgCount1: 0; zeroWinCount0: 3, zeroWinCount1: 5
		},
		flowPerfStats:{
			artSum: 6, artCount: 1; rttSyn0: 10, rttSyn1: 1;
			rtt0Sum: 26, rtt0Count: 2; rtt1Sum: 101, rtt1Count: 2;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCount0: 0, pshUrgCount1: 0; zeroWinCount0: 3, zeroWinCount1: 5
		}
	*/
}

func testReport(flowPerf *MetaFlowPerf, out bool) {
	var report *TcpPerfStats
	var periodData, flowData *MetaPerfStats

	periodData = flowPerf.perfData.periodPerfStats
	flowData = flowPerf.perfData.flowPerfStats
	periodData.artSum = 100
	flowData.artSum += periodData.artSum
	periodData.artCount = 1
	flowData.artCount += periodData.artCount
	report = flowPerf.Report()
	if out {
		fmt.Printf("flowperf.perfData:%v\nreport:%v\n", flowPerf.perfData, report)
	}

	periodData = flowPerf.perfData.periodPerfStats
	flowData = flowPerf.perfData.flowPerfStats
	periodData.artSum = 200
	flowData.artSum += periodData.artSum
	periodData.artCount = 1
	flowData.artCount += periodData.artCount
	periodData.rtt0Sum = 1000
	flowData.rtt0Sum += periodData.rtt0Sum
	periodData.rtt0Count = 1
	flowData.rtt0Count += periodData.rtt0Count
	report = flowPerf.Report()
	if out {
		fmt.Printf("flowperf.perfData:%v\nreport:%v\n", flowPerf.perfData, report)
	}
}

func TestReport(t *testing.T) {
	flowPerf := NewMetaFlowPerf()
	testReport(flowPerf, true)
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

func BenchmarkUpdate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testMetaFlowPerfUpdate()
	}
}

func BenchmarkReport(b *testing.B) {
	output := false
	flowPerf := NewMetaFlowPerf()

	for i := 0; i < b.N; i++ {
		testReport(flowPerf, output)
	}
}
