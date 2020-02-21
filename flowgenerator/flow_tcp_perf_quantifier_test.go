package flowgenerator

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func loadPcap(file string) ([]RawPacket, []uint16, []time.Duration, error) {
	var f *os.File
	var err error
	dirName := "flowgenerator"
	cwd, _ := os.Getwd()
	if strings.Contains(cwd, dirName) {
		f, err = os.Open(file)
	} else { // dlv
		f, err = os.Open(dirName + "/" + file)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	r, _ := pcapgo.NewReader(f)
	var packets []RawPacket
	var packetLens []uint16
	var packetStamps []time.Duration
	for {
		packet, ci, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}
		packetLens = append(packetLens, uint16(ci.Length))
		packetStamps = append(packetStamps, time.Duration(ci.Timestamp.UnixNano()))
		if len(packet) > 128 {
			packets = append(packets, packet[:128])
		} else {
			packets = append(packets, packet)
		}
	}
	return packets, packetLens, packetStamps, err
}

func getMetaPacketFromPcap(file string) ([]*MetaPacket, error) {
	raw, lens, ts, err := loadPcap(file)
	if err != nil {
		return nil, err
	}

	packets := make([]*MetaPacket, 0, len(raw))
	for i, pkt := range raw {
		meta := &MetaPacket{PacketLen: lens[i], Timestamp: ts[i]}
		l2Len := meta.ParseL2(pkt)
		meta.Parse(pkt[l2Len:])
		packets = append(packets, meta)
	}

	return packets, nil
}

func getPacketDirection(first, packet *MetaPacket) bool {
	return first.IpSrc == packet.IpSrc
}

func perfTestTemplate(t *testing.T, pcapFile string, resultFile string, careSeqList bool) {
	var buffer bytes.Buffer
	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()
	flowExtra := &FlowExtra{
		taggedFlow: &TaggedFlow{},
	}

	packets, err := getMetaPacketFromPcap(pcapFile)
	if err != nil {
		t.Errorf("structure metaPacket faild as %v", err)
		return
	}
	if len(packets) < 2 {
		t.Logf("calc flow perf need minimum 2 packets")
		return
	}

	firstPkt := packets[0]
	for i, pkt := range packets {
		if pkt.TcpData.DataOffset == 0 {
			t.Errorf("raw packet not tcp packet, %vth meta_packet is %v", i, pkt)
		}

		flowPerf.Update(pkt, getPacketDirection(firstPkt, pkt), flowExtra, &counter)
		buffer.WriteString(fmt.Sprintf("\t%vth perf data:%v", i, flowPerf.perfData))
		if careSeqList {
			session := flowPerf.ctrlInfo.tcpSession
			buffer.WriteString(fmt.Sprintf("\t\tclient seqList(len:%v):%v\n\t\tserver seqList(len:%v):%v\n",
				session[0].arraySize, session[0].seqArray, session[1].arraySize, session[1].seqArray))
		}
	}

	content, _ := ioutil.ReadFile(resultFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("actual.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to actual.txt", resultFile))
	}
}

func TestRttSyn(t *testing.T) {
	perfTestTemplate(t, "rtt_syn_2_ack.pcap", "flowPerf_rttSyn_test.result", false)
}

func TestArt(t *testing.T) {
	perfTestTemplate(t, "art-continues-payload-len-larger-than-1.pcap", "flowPerf_art_test.result", false)
}

func TestRetrans(t *testing.T) {
	perfTestTemplate(t, "xiangdao-retrans.pcap", "flowPerf_xiangdao-retrans_test.result", true)
}

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
		peer.insertSeqListNode(*node, peer.arraySize/2)
		peer.mergeSeqListNode(peer.arraySize / 2)
	case 1:
		peer.insertSeqListNode(*node, peer.arraySize)
		peer.mergeSeqListNode(peer.arraySize - 2)
	default:
	}
}

func TestMergeSeqListNode(t *testing.T) {
	var tcpHeader *MetaPacketTcpHeader
	var payload uint16
	var node *SeqSegment
	peer := &TcpSessionPeer{}

	// insert{100, 10},{200,10}, ... , {(SEQ_LIST_MAX_LEN-1)*100, 10}
	for i := 1; i <= SEQ_LIST_MAX_LEN; i++ {
		tcpHeader = &MetaPacketTcpHeader{Seq: uint32(100 * i), Ack: 20}
		payload = 10
		peer.assertSeqNumber(tcpHeader, payload)
	}
	//t.Log(peer.String())

	// test case {10, 10}
	node = &SeqSegment{seqNumber: uint32(SEQ_LIST_MAX_LEN*100 + 10), length: 10}
	testMergeSeqListNode(peer, node, -1)
	// {10, 100}
	//t.Log(peer.String())

	// test case {320, 10}
	node = &SeqSegment{seqNumber: 320, length: 10}
	testMergeSeqListNode(peer, node, 0)
	// {10, 200}
	//t.Log(peer.String())

	// {SEQ_LIST_MAX_LEN*10+10, 10}
	node = &SeqSegment{seqNumber: 10, length: 10}
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
		t.Errorf("result is %v, expected %v", flag, SEQ_NOT_CARE)
		return
	}

	if flag := peer.assertSeqNumber(&MetaPacketTcpHeader{Seq: 0}, 1); flag != SEQ_NOT_CARE {
		t.Errorf("result is %v, expected %v", flag, SEQ_NOT_CARE)
		return
	}
	// {0, 1}

	// {10, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10, Ack: 20}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_NOT_CARE {
		t.Errorf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
		t.Errorf("actual is %v, expected {10,10}", peer.String())
		return
	}

	// {20, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 20}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
		t.Errorf("actual is %v, expected {10,20}", peer.String())
		return
	}
	// {10,20}

	// right.seqNo+right.payload >= node.seqNo+node.len
	// input test case {10, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_RETRANS {
		t.Errorf("result is %v, expected %v", flag, SEQ_RETRANS)
		t.Errorf("actual is %v, expected {10,20}", peer.String())
		return
	}
	// {10, 20}

	// right.seqNo+right.payload >= node.seqNo+node.len
	// input test case {10, 10}
	tcpHeader = &MetaPacketTcpHeader{Seq: 20}
	payload = 10
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_RETRANS {
		t.Errorf("result is %v, expected %v", flag, SEQ_RETRANS)
		t.Errorf("actual is %v, expected {10,20}", peer.String())
		return
	}
	// {10, 20}

	// 测试例 else node.seqNo < right.seqNo+right.len
	//{40, 20}, 异常情况{10,21},{29, 5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 40}
	payload = 20
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
		t.Errorf("actual is %v, expected{40,20},{10,20}", peer.String())
		return
	}
	//{40,20},{10,20}

	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 21
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Errorf("result is %v, expected %v", flag, SEQ_ERROR)
		t.Errorf("actual is %v, expected{40,20},{10,20}", peer.String())
		return
	}
	//{40,20},{10,20}

	tcpHeader = &MetaPacketTcpHeader{Seq: 29}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Errorf("result is %v, expected %v", flag, SEQ_ERROR)
		t.Errorf("actual is %v, expected{40,20},{10,20}", peer.String())
		return
	}
	//{40,20},{10,20}

	//{40,20},{10,20}
	// 测试例 left.seqNo <= node.seqNo
	// 测试例 node.seqNo+node.payload <= left.seqNo+left.len
	// {10,20}
	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 20
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_RETRANS {
		t.Errorf("result is %v, expected %v", flag, SEQ_RETRANS)
		t.Errorf("actual is %v, expected{40,20},{10,20}", peer.String())
		return
	}
	//{40,20},{10,20}

	// 测试例 node.seqNo > left.seqNo+left.payload && node.seqNo+node.payload < right.seqNo
	// {31,4}
	tcpHeader = &MetaPacketTcpHeader{Seq: 31}
	payload = 4
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
		t.Errorf("actual is %v, expected{40,20},{31,4},{10,20}", peer.String())
		return
	}
	//{40,20},{31,4},{10,20}

	// 测试例 else node.seqNo == left.seqNo+left.payload || node.seqNo+node.payload == right.seqNo
	// {30,1}, {35,2}, {39,1}/*异常情况{38, 7}, {10,28}, {35,5}*/
	tcpHeader = &MetaPacketTcpHeader{Seq: 30}
	payload = 1
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS_BOTH {
		t.Errorf("result is %v, expected %v", flag, SEQ_CONTINUOUS_BOTH)
		t.Errorf("actual is %v, expected{40,20},{10,25}", peer.String())
		return
	}
	//{40,20},{10,25}

	tcpHeader = &MetaPacketTcpHeader{Seq: 35}
	payload = 2
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
		t.Errorf("actual is %v, expected{40,20},{10,27}", peer.String())
		return
	}
	//{40,20},{10,27}

	tcpHeader = &MetaPacketTcpHeader{Seq: 39}
	payload = 1
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
		t.Errorf("actual is %v, expected{39,21},{10,27}", peer.String())
		return
	}
	//{39,21},{10,27}

	// 异常情况{38, 7}, {10,28}, {35,5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 38}
	payload = 7
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Errorf("result is %v, expected %v", flag, SEQ_ERROR)
		t.Errorf("actual is %v, expected{39,21},{10,27}", peer.String())
		return
	}
	//{39,21},{10,27}

	tcpHeader = &MetaPacketTcpHeader{Seq: 10}
	payload = 28
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Errorf("result is %v, expected %v", flag, SEQ_ERROR)
		t.Errorf("actual is %v, expected{39,21},{10,27}", peer.String())
		return
	}
	//{39,21},{10,27}

	tcpHeader = &MetaPacketTcpHeader{Seq: 35}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_ERROR {
		t.Errorf("result is %v, expected %v", flag, SEQ_ERROR)
		t.Errorf("actual is %v, expected{39,21},{10,27}", peer.String())
		return
	}
	//{39,21},{10,27}

	// 测试例 else /*left.seqNo > node.seqNo*/
	// 测试例 left.seqNo == node.seqNo+node.len
	// {5,5}
	tcpHeader = &MetaPacketTcpHeader{Seq: 5}
	payload = 5
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_CONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_CONTINUOUS)
		t.Errorf("actual is %v, expected{39,21},{5,32}", peer.String())
		return
	}
	//{39,21},{5,32}

	// {1,3}
	tcpHeader = &MetaPacketTcpHeader{Seq: 1}
	payload = 3
	if flag := peer.assertSeqNumber(tcpHeader, payload); flag != SEQ_DISCONTINUOUS {
		t.Errorf("result is %v, expected %v", flag, SEQ_DISCONTINUOUS)
		t.Errorf("actual is %v, expected{39,21},{5,32},{1,3}", peer.String())
		return
	}
	//{39,21},{5,32},{1,3}

	expected := [3]SeqSegment{{39, 21}, {5, 32}, {1, 3}}
	for i, n := range expected {
		if n.seqNumber != peer.seqArray[i].seqNumber ||
			n.length != peer.seqArray[i].length {
			t.Errorf("result: %v", peer.seqArray)
			t.Errorf("expected: %v", expected)
			break
		}
	}
}

func TestReestablishFsm(t *testing.T) {
	var packetHeader *MetaPacket

	counter := NewFlowPerfCounter()
	flowPerf := AcquireMetaFlowPerf()
	perfCtrl := flowPerf.ctrlInfo
	//perfData := flowPerf.perfData
	client := &perfCtrl.tcpSession[0]
	server := &perfCtrl.tcpSession[1]

	// 1SYN -> 2SYN/ACK -> 1ACK -> 1ACK/LEN>0 -> 2ACK -> 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0
	// 1SYN
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}, Timestamp: 3333, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, true, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 2SYN/ACK rttSyn1 = 1
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}, Timestamp: 3334, PayloadLen: 0}
	flowPerf.update(server, client, packetHeader, false, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 1ACK rttSyn0 = 10
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}, Timestamp: 3344, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, true, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 1ACK/LEN>0 len=100
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}, Timestamp: 3350, PayloadLen: 100}
	flowPerf.update(client, server, packetHeader, true, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 2ACK rtt1 = 4
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}, Timestamp: 3354, PayloadLen: 0}
	flowPerf.update(server, client, packetHeader, false, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 2ACK/LEN>0 len=500 art1 = 30
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1112, Ack: 212}, Timestamp: 3384, PayloadLen: 500}
	flowPerf.update(server, client, packetHeader, false, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	server.updateData(packetHeader)

	// 1ACK rtt0 = 16
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}, Timestamp: 3400, PayloadLen: 0}
	flowPerf.update(client, server, packetHeader, true, &counter)
	//t.Logf("%v, %v, %v", client.String(), server.String(), perfData)
	client.updateData(packetHeader)

	// 1ACK/LEN>0 len=200 art0 = 54
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1612}, Timestamp: 3454, PayloadLen: 200}
	flowPerf.update(client, server, packetHeader, true, &counter)
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
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{DataOffset: 5, Flags: TCP_SYN | TCP_ACK | TCP_PSH | TCP_URG}, Timestamp: 1000}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != true {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	//  ACK组合
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{DataOffset: 5, Flags: TCP_ACK /*| TCP_FIN | TCP_RST*/ | TCP_PSH | TCP_URG}}
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

	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{DataOffset: 5, Flags: TCP_RST}}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}

	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{DataOffset: 5, Flags: TCP_FIN}}
	if ok := flowPerf.preprocess(packetHeader, &counter); ok != false {
		t.Errorf("tcpflag:0x%04x, faild\n", tcpHeader.Flags)
	}
}

// call Update 11 times
func testMetaFlowPerfUpdate(t *testing.T) {
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
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_SYN, Seq: 111, Ack: 0}, Timestamp: 3333, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2SYN/ACK rttSyn1=1
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_SYN | TCP_ACK, Seq: 1111, Ack: 112}, Timestamp: 3334, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 1ACK rttSyn0=10
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}, Timestamp: 3344, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 1ACK/LEN>0 len=100
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 112, Ack: 1112}, Timestamp: 3350, PayloadLen: 100}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2ACK/LEN>0包，len=100 *art1=4
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1112, Ack: 212}, Timestamp: 3354, PayloadLen: 100}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK 测试连续ACK包, 对RTT计算的影响
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1212, Ack: 212}, Timestamp: 3358, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK/LEN>0 len=500
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_PSH | TCP_ACK, Seq: 1212, Ack: 212}, Timestamp: 3384, PayloadLen: 500}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 1ACK rtt0=16
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}, Timestamp: 3400, PayloadLen: 0}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 1ACK/LEN>0 len=200 art0=70
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 212, Ack: 1712}, Timestamp: 3454, PayloadLen: 200}
	flowPerf.Update(packetHeader, false, flowExtra, &counter)

	// 2ACK *rtt1=100
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}, Timestamp: 3554, PayloadLen: 0}
	flowPerf.Update(packetHeader, true, flowExtra, &counter)

	// 2ACK/LEN>0 len=300 *art1=106
	packetHeader = &MetaPacket{TcpData: MetaPacketTcpHeader{Flags: TCP_ACK, Seq: 1712, Ack: 412}, Timestamp: 3560, PayloadLen: 300}
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

	report = copyAndResetPerfData(flowPerf, false, &counter)

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
	report = copyAndResetPerfData(flowPerf, true, &counter)

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
	perf = copyAndResetPerfData(p, false, &counter)
	t.Log(p.perfData.packetVariance)
	t.Log(perf)

	header = &MetaPacket{
		PacketLen: 4000,
		Timestamp: 6000,
	}
	p.calcVarianceStats(header, 2)
	perf = copyAndResetPerfData(p, false, &counter)
	t.Log(p.perfData.packetVariance)
	t.Log(perf)

	header = &MetaPacket{
		PacketLen: 64,
		Timestamp: 3000000,
	}
	p.calcVarianceStats(header, 3)
	perf = copyAndResetPerfData(p, false, &counter)
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
