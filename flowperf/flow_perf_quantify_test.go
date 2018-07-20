package flowperf

import (
	"container/list"
	"fmt"
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"

	"gitlab.x.lan/yunshan/droplet/handler"
)

func testTcpSessionPeerSeqNoMerge(peer TcpSessionPeer, left, right, node *SeqSegment, t *testing.T) {
	if left == nil || right == nil || node == nil || t == nil {
		return
	}

	ret := peer.isContinuousSeqSegment(left, right, node)
	if ret == SEQ_NODE_DISCONTINUOUS {
		t.Logf("%s test faild\n", t.Name())
	}
}

func TestTcpSessionPeerSeqNoMerge(t *testing.T) {
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
	testTcpSessionPeerSeqNoMerge(peer, left, right, node, t)

	//{51,5}, nil
	node = &SeqSegment{56, 4}
	left = e5.Value.(*SeqSegment)
	right = nil
	testTcpSessionPeerSeqNoMerge(peer, left, right, node, t)

	//{31,10},{51,5}
	node = &SeqSegment{41, 10}
	left = e4.Value.(*SeqSegment)
	right = e5.Value.(*SeqSegment)
	testTcpSessionPeerSeqNoMerge(peer, left, right, node, t)
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

func TestTcpSessionPeerSeqNoAssert(t *testing.T) {
	var tcphdr *handler.MetaPktTcpHdr
	var payload uint16
	var l *list.List

	peer := &TcpSessionPeer{}

	// 测试例 payload == 0
	peer.assertSeqNumber(&handler.MetaPktTcpHdr{}, 0)

	peer.assertSeqNumber(&handler.MetaPktTcpHdr{}, 1)

	// init list
	if peer.seqList == nil {
		peer.seqList = list.New()
		l = peer.seqList
	}

	// list is empty, insert {20, 10}
	if l.Len() == 0 {
		tcphdr = &handler.MetaPktTcpHdr{Seq: 10, Ack: 20}
		payload = 10
		peer.assertSeqNumber(tcphdr, payload)
	}

	// {20, 10}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 20}
	payload = 10
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}
	t.Log(peer.String())

	// right.seqNo+right.payload >= node.seqNo+node.len
	// input test case {10, 10}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 10}
	payload = 10
	peer.assertSeqNumber(tcphdr, payload)
	// {10, 20}
	t.Log(peer.String())

	//	测试例 else node.seqNo < right.seqNo+right.len
	//  {40, 20}, 异常情况{10,21}, {29, 5}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 40}
	payload = 20
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 10}
	payload = 21
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 29}
	payload = 5
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	// {10,20}, {40,20}
	// 测试例 left.seqNo <= node.seqNo
	// 测试例 node.seqNo+node.payload <= left.seqNo+left.len
	// {10,20}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 10}
	payload = 20
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}, {40,20}
	t.Log(peer.String())

	// 测试例 node.seqNo > left.seqNo+left.payload && node.seqNo+node.payload < right.seqNo
	// {31,4}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 31}
	payload = 4
	peer.assertSeqNumber(tcphdr, payload)
	// {10,20}, {31,4}, {40,20}
	t.Log(peer.String())

	// 测试例 else node.seqNo == left.seqNo+left.payload || node.seqNo+node.payload == right.seqNo
	// {30,1}, {35,2}, {39,1}/*异常情况{38, 7}, {10,28}, {35,5}*/
	tcphdr = &handler.MetaPktTcpHdr{Seq: 30}
	payload = 1
	peer.assertSeqNumber(tcphdr, payload)
	// {10,25}, {40,20}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 35}
	payload = 2
	peer.assertSeqNumber(tcphdr, payload)
	// {10,27}, {40,20}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 39}
	payload = 1
	peer.assertSeqNumber(tcphdr, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	// 异常情况{38, 7}, {10,28}, {35,5}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 38}
	payload = 7
	peer.assertSeqNumber(tcphdr, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 10}
	payload = 28
	peer.assertSeqNumber(tcphdr, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	tcphdr = &handler.MetaPktTcpHdr{Seq: 35}
	payload = 5
	peer.assertSeqNumber(tcphdr, payload)
	// {10,27}, {39,21}
	t.Log(peer.String())

	// 测试例 else /*left.seqNo > node.seqNo*/
	// 测试例 left.seqNo == node.seqNo+node.len
	// {5,5}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 5}
	payload = 5
	peer.assertSeqNumber(tcphdr, payload)
	// {5,33}, {39,21}
	t.Log(peer.String())

	// {1,3}
	tcphdr = &handler.MetaPktTcpHdr{Seq: 1}
	payload = 3
	peer.assertSeqNumber(tcphdr, payload)
	// {1,3}, {5,33}, {39,21}
	t.Log(peer.String())
}

func TestFlowPerfCtrlInfoFirstPacket(t *testing.T) {
	client := TcpSessionPeer{seqList: list.New()}
	server := TcpSessionPeer{seqList: list.New()}
	perfCtrl := &FlowPerfCtrlInfo{ /*isFirstPkt: true, */ tcpSession: TcpConnSession{client, server}}

	input, expected := make([]interface{}, 2), make([]interface{}, 2)
	// output := expected //output， expected引用相同的底层，相当于指针指向同一地址
	output := make([]interface{}, 2)

	// SYN
	tcphdr := handler.MetaPktTcpHdr{Flags: TCP_SYN, Seq: 123, Ack: 321}
	pkthdr := &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 5678, PayloadLen: 0}
	perfCtrl.firstPacket(pkthdr)
	input[0] = tcphdr
	input[1] = pkthdr
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
	perfCtrl = &FlowPerfCtrlInfo{ /*isFirstPkt: true, */ tcpSession: TcpConnSession{client, server}}
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN | TCP_ACK, Seq: 124, Ack: 421}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 6678, PayloadLen: 0}
	perfCtrl.firstPacket(pkthdr)
	input[0] = tcphdr
	input[1] = pkthdr
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
	perfCtrl = &FlowPerfCtrlInfo{ /*isFirstPkt: true, */ tcpSession: TcpConnSession{client, server}}
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 125, Ack: 521}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 7678, PayloadLen: 0}
	perfCtrl.firstPacket(pkthdr)
	input[0] = tcphdr
	input[1] = pkthdr
	l0 = list.New()
	expected[0] = TcpSessionPeer{seq: 125, payloadLen: 0, timestamp: 7678, tcpState: TCP_STATE_ESTABLISHED,
		seqList: l0}
	l1 = list.New()
	expected[1] = TcpSessionPeer{tcpState: TCP_STATE_ESTABLISHED, seqList: l1}
	output[0] = perfCtrl.tcpSession[0]
	output[1] = perfCtrl.tcpSession[1]
}

func TestReestablishFsm(t *testing.T) {
	var tcphdr handler.MetaPktTcpHdr
	var pkthdr *handler.MetaPktHdr
	var direction bool

	flowPerf := NewMetaFlowPerf()
	perfCtrl := flowPerf.ctrlInfo
	perfData := flowPerf.perfData
	client := &perfCtrl.tcpSession[0]
	server := &perfCtrl.tcpSession[1]
	// 1SYN -> 2SYN/ACK -> 1ACK -> 1ACK/LEN>0 -> 2ACK -> 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0
	// 1SYN
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN, Seq: 111, Ack: 0}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3333, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2SYN/ACK rttSyn1
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3334, PayloadLen: 0}
	flowPerf.reestablishFsm(server, client, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK rttSyn0
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3344, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK/LEN>0 len=100
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3350, PayloadLen: 100}
	flowPerf.reestablishFsm(client, server, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2ACK rttS1
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3354, PayloadLen: 0}
	flowPerf.reestablishFsm(server, client, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 2ACK/LEN>0 len=500 art
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_PSH | TCP_ACK, Seq: 1112, Ack: 212}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3384, PayloadLen: 500}
	flowPerf.reestablishFsm(server, client, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK rttS0
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3400, PayloadLen: 0}
	flowPerf.reestablishFsm(client, server, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)

	// 1ACK/LEN>0 len=200
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 212, Ack: 1612}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3454, PayloadLen: 200}

	flowPerf.reestablishFsm(client, server, pkthdr, direction)
	t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
}

func TestNewMetaFlowPerf(t *testing.T) {
	flowPerf := NewMetaFlowPerf()
	t.Log(flowPerf.ctrlInfo, flowPerf.perfData, /*, flowPerf.counter*/
		flowPerf.ctrlInfo.tcpSession[0].seqList.PushFront(&SeqSegment{111, 11}))
	/*
		flow_perf_quantify_test.go:346: &{[{0xc42001f0e0 0 0 0 0 0 0 false false} {0xc42001f110 0 0 0 0 0 0 false false}]}
		reportPerfStat:{
			SynRetransCnt0: 0, SynRetransCnt1: 0;
			ARTAvg: 0, RTTSyn: 0, RTT: 0, RTTAvg: 0;
			RetransCnt0: 0, RetransCnt1: 0, TotalRetransCnt: 0;
			ZeroWndCnt0: 0; ZeroWndCnt1: 0, TotalZeroWndCnt: 0;
			SlowStartCnt0: 0, SlowStartCnt1: 0, TotalSlowStartCnt: 0;
			PshUrgCnt0: 0, PshUrgCnt1: 0, TotalPshUrgCnt: 0
		},
		periodPerfStat:{
			artSum: 0, artCnt: 0; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 0, rtt0Cnt: 0; rtt1Sum: 0, rtt1Cnt: 0;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCnt0: 0, pshUrgCnt1: 0; zeroWndCnt0: 0, zeroWndCnt1: 0
		},
		flowPerfStat:{
			artSum: 0, artCnt: 0; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 0, rtt0Cnt: 0; rtt1Sum: 0, rtt1Cnt: 0;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCnt0: 0, pshUrgCnt1: 0; zeroWndCnt0: 0, zeroWndCnt1: 0
		} &{0xc42001f0e0 0xc42001f0e0 0xc42001f0e0 0xc421228a30}
	*/
}

func TestPreprocess(t *testing.T) {
	var tcphdr handler.MetaPktTcpHdr
	var pkthdr *handler.MetaPktHdr

	flowPerf := NewMetaFlowPerf()

	//  SYN组合
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN | TCP_ACK | TCP_PSH | TCP_URG}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 1000}
	if ok := flowPerf.preprocess(pkthdr); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcphdr.Flags)
	}

	//  ACK组合
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK /*| TCP_FIN | TCP_RST*/ | TCP_PSH | TCP_URG}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr}
	if ok := flowPerf.preprocess(pkthdr); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcphdr.Flags)
	}
	/*
		//  SYN异常组合
		tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN | TCP_RST | TCP_FIN}
		pkthdr = &handler.MetaPktHdr{TcpData: tcphdr}
		if ok := flowPerf.preprocess(pkthdr); ok != false {
			t.Errorf("tcpflag:0x%04x, faild, result:%v\n", tcphdr.Flags, ok)
		}

		//  FIN异常组合
		tcphdr = handler.MetaPktTcpHdr{Flags: TCP_FIN | TCP_PSH | TCP_URG}
		pkthdr = &handler.MetaPktHdr{TcpData: tcphdr}
		if ok := flowPerf.preprocess(pkthdr); ok != false {
			t.Errorf("tcpflag:0x%04x, faild\n", tcphdr.Flags)
		}
	*/

	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_RST}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr}
	if ok := flowPerf.preprocess(pkthdr); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcphdr.Flags)
	}

	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_FIN}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr}
	if ok := flowPerf.preprocess(pkthdr); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcphdr.Flags)
	}
}

func testMetaFlowPerfUpdate() {
	var tcphdr handler.MetaPktTcpHdr
	var pkthdr *handler.MetaPktHdr
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
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN, Seq: 111, Ack: 0}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3333, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 2SYN/ACK rttSyn1=1
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3334, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 1ACK rttSyn0=10
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3344, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 1ACK/LEN>0 len=100
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 112, Ack: 1112}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3350, PayloadLen: 100}
	flowPerf.Update(pkthdr, direction)

	// 测试连续2ACK/LEN>0包，len=100, 对RTT计算的影响
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 1112, Ack: 212}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3354, PayloadLen: 100}
	flowPerf.Update(pkthdr, direction)

	// 2ACK
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 1212, Ack: 212}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3358, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 2ACK/LEN>0 len=500
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_PSH | TCP_ACK, Seq: 1212, Ack: 212}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3384, PayloadLen: 500}
	flowPerf.Update(pkthdr, direction)

	// 1ACK rtt0=16
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3400, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 1ACK/LEN>0 len=200
	direction = false
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 212, Ack: 1712}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3454, PayloadLen: 200}
	flowPerf.Update(pkthdr, direction)

	// 2ACK rtt1=100
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3554, PayloadLen: 0}
	flowPerf.Update(pkthdr, direction)

	// 2ACK/LEN>0 len=300 art=6
	direction = true
	tcphdr = handler.MetaPktTcpHdr{Flags: TCP_ACK, Seq: 1712, Ack: 412}
	pkthdr = &handler.MetaPktHdr{TcpData: tcphdr, Timestamp: 3560, PayloadLen: 300}
	flowPerf.Update(pkthdr, direction)

}

func TestMetaFlowPerfUpdate(t *testing.T) {
	testMetaFlowPerfUpdate()
	/*
		reportPerfStat:{
			SynRetransCnt0: 0, SynRetransCnt1: 0;
			ARTAvg: 0, RTTSyn: 0, RTT: 0, RTTAvg: 0;
			RetransCnt0: 0, RetransCnt1: 0, TotalRetransCnt: 0;
			ZeroWndCnt0: 0; ZeroWndCnt1: 0, TotalZeroWndCnt: 0;
			SlowStartCnt0: 0, SlowStartCnt1: 0, TotalSlowStartCnt: 0;
			PshUrgCnt0: 0, PshUrgCnt1: 0, TotalPshUrgCnt: 0
		},
		periodPerfStat:{
			artSum: 6, artCnt: 1; rttSyn0: 0, rttSyn1: 0;
			rtt0Sum: 16, rtt0Cnt: 1; rtt1Sum: 100, rtt1Cnt: 1;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCnt0: 0, pshUrgCnt1: 0; zeroWndCnt0: 3, zeroWndCnt1: 5
		},
		flowPerfStat:{
			artSum: 6, artCnt: 1; rttSyn0: 10, rttSyn1: 1;
			rtt0Sum: 26, rtt0Cnt: 2; rtt1Sum: 101, rtt1Cnt: 2;
			retrans0: 0, retrans1: 0; retransSyn0: 0, retransSyn1: 0;
			pshUrgCnt0: 0, pshUrgCnt1: 0; zeroWndCnt0: 3, zeroWndCnt1: 5
		}
	*/
}

func testReport(flowPerf *MetaFlowPerf, out bool) {
	var report *TcpPerfStat
	var periodData, flowData *MetaPerfStat

	periodData = flowPerf.perfData.periodPerfStat
	flowData = flowPerf.perfData.flowPerfStat
	periodData.artSum = 100
	flowData.artSum += periodData.artSum
	periodData.artCnt = 1
	flowData.artCnt += periodData.artCnt
	report = flowPerf.Report()
	if out {
		fmt.Printf("flowperf.perfData:%v\nreport:%v\n", flowPerf.perfData, report)
	}

	periodData = flowPerf.perfData.periodPerfStat
	flowData = flowPerf.perfData.flowPerfStat
	periodData.artSum = 200
	flowData.artSum += periodData.artSum
	periodData.artCnt = 1
	flowData.artCnt += periodData.artCnt
	periodData.rtt0Sum = 1000
	flowData.rtt0Sum += periodData.rtt0Sum
	periodData.rtt0Cnt = 1
	flowData.rtt0Cnt += periodData.rtt0Cnt
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
	return err.returnErr()
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
