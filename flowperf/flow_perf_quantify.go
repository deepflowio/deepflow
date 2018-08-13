package flowperf

import (
	"container/list"
	"fmt"
	"reflect"
	"runtime"
	"time"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/handler"
	"gitlab.x.lan/yunshan/droplet/utils"
)

var log = logging.MustGetLogger(FP_NAME)

type ContinuousFlag uint8
type TcpConnState uint8
type TcpConnSession [2]TcpSessionPeer

const (
	FP_NAME = "flowperf"
)

const (
	TCP_DIR_CLIENT = false
	TCP_DIR_SERVER = true
)

const (
	TCP_FIN = 1 << iota //: 0x001
	TCP_SYN             //: 0x002
	TCP_RST             //: 0x004
	TCP_PSH             //: 0x008
	TCP_ACK             //: 0x010
	TCP_URG             //: 0x020
	TCP_ECE             //: 0x040
	TCP_CWR             //: 0x080
	TCP_NS              //: 0x100
)

// standard
const (
	TCP_STATE_CLOSED TcpConnState = iota
	TCP_STATE_LISTEN
	TCP_STATE_SYN_SENT
	TCP_STATE_SYN_RECV
	TCP_STATE_ESTABLISHED
	TCP_STATE_CLOSE_WAIT
	TCP_STATE_FIN_WAIT_1
	TCP_STATE_CLOSING
	TCP_STATE_LAST_ACK
	TCP_STATE_FIN_WAIT_2
	TCP_STATE_TIME_WAIT
	TCP_STATE_MAX_NUM
)

const (
	SEQ_NODE_DISCONTINUOUS   ContinuousFlag = 0
	SEQ_NODE_LEFT_CONTINUOUS                = 1 << iota
	SEQ_NODE_RIGHT_CONTINUOUS
	SEQ_NODE_BOTH_CONTINUOUS = SEQ_NODE_LEFT_CONTINUOUS | SEQ_NODE_RIGHT_CONTINUOUS
)

const (
	SEQ_ERROR = iota
	SEQ_CONTINUOUS
	SEQ_DISCONTINUOUS
	SEQ_RETRANS
)

const (
	WIN_SCALE_MAX     = 14
	WIN_SCALE_MASK    = 0x0f
	WIN_SCALE_FLAG    = 0x80
	WIN_SCALE_UNKNOWN = 0x40
)

type SeqSegment struct { // 避免乱序，识别重传
	seqNumber uint32
	length    uint32
}

type TcpSessionPeer struct {
	seqList *list.List // 升序链表, 内容为SeqSegment

	tcpState   TcpConnState
	timestamp  time.Duration
	seq        uint32
	payloadLen uint32
	winSize    uint16
	winScale   uint8

	canCalcRtt bool
	canCalcArt bool
}

type FlowPerfCtrlInfo struct {
	tcpSession TcpConnSession
}

// art---Application Response Time
// 现有3个连续包PSH/ACK--ACK--PSH/ACK,其中第一个包是client端的请求包，
// 后2个包是server端的应答包，art表示后2个包之间的时间间隔
type MetaPerfStat struct {
	artCnt, rtt0Cnt, rtt1Cnt uint32
	artSum, rtt0Sum, rtt1Sum time.Duration
	rttSyn0, rttSyn1         time.Duration

	retrans0, retrans1       uint32
	retransSyn0, retransSyn1 uint32

	pshUrgCnt0, pshUrgCnt1   uint32
	zeroWndCnt0, zeroWndCnt1 uint32
}

type FlowPerfDataInfo struct {
	reportPerfStat *TcpPerfStat // OUT
	periodPerfStat *MetaPerfStat
	flowPerfStat   *MetaPerfStat
}

type FlowPerfCounter struct {
	validRttSynTimes     uint32 `statsd:"rtt_syn_times"`     // Flow中某个满足rttSyn计算的地方计数加1
	validRttTimes        uint32 `statsd:"rtt_times"`         // Flow中某个满足rtt计算的地方计数加1
	validArtTimes        uint32 `statsd:"art_times"`         // Flow中某个满足art计算的地方计数加1
	validRetransTimes    uint32 `statsd:"retrans_times"`     // Flow中某个Packet发生多次重传计数加1
	validSynRetransTimes uint32 `statsd:"syn_retrans_times"` // Flow中在连接建立阶段，某个Packet发生多次重传计数加1
	invalidPktCnt        uint32 `statsd:"invalid_packet"`    // Flow中某个识别为异常包的地方计数加1
	unknownPktCnt        uint32 `statsd:"unknown_packet"`    // Flow中某个识别为unknown包的地方计数加1
}

type MetaFlowPerf struct {
	ctrlInfo *FlowPerfCtrlInfo
	perfData *FlowPerfDataInfo
	counter  *FlowPerfCounter // OUT
}

func (t *TcpSessionPeer) setArtPrecondition() {
	t.canCalcArt = true
}

func (t *TcpSessionPeer) resetArtPrecondition() {
	t.canCalcArt = false
}

func (t *TcpSessionPeer) setRttPrecondition() {
	t.canCalcRtt = true
}

func (t *TcpSessionPeer) resetRttPrecondition() {
	t.canCalcRtt = false
}

func (t *TcpSessionPeer) getArtPrecondition() bool {
	return t.canCalcArt
}

func (t *TcpSessionPeer) getRttPrecondition() bool {
	return t.canCalcRtt
}

func (p *TcpSessionPeer) isContinuousSeqSegment(left, right, node *SeqSegment) ContinuousFlag {
	flag := SEQ_NODE_DISCONTINUOUS

	if node == nil {
		log.Errorf("node is nil")
		return SEQ_NODE_DISCONTINUOUS
	}

	log.Debugf("node: {%v,%v}", node.seqNumber, node.length)
	if left != nil && left.seqNumber+left.length == node.seqNumber {
		left.length += node.length
		log.Debugf("left merge: {%v,%v}", left.seqNumber, left.length)

		flag |= SEQ_NODE_LEFT_CONTINUOUS
	}

	if right != nil && node.seqNumber+node.length == right.seqNumber {
		right.seqNumber = node.seqNumber
		right.length += node.length
		log.Debugf("right merge: {%v,%v}", right.seqNumber, right.length)

		flag |= SEQ_NODE_RIGHT_CONTINUOUS
	}

	return flag
}

// 根据seqNumber判断包重传,连续,不连续
// 合并连续seqNumber
// 不连续则添加新节点, 构建升序链表
func (p *TcpSessionPeer) assertSeqNumber(tcphdr *handler.MetaPacketTcpHeader, payloadLen uint16) uint32 {
	var flag uint32
	var left, right *SeqSegment
	var e *list.Element

	if payloadLen == 0 {
		log.Infof("error input, payloadLen==0")
		return SEQ_ERROR
	}

	node := &SeqSegment{seqNumber: tcphdr.Seq, length: uint32(payloadLen)}
	log.Debugf("node: %v", node)

	l := p.seqList
	if l == nil {
		log.Errorf("seqNumber list is nil, seqNumber data have lost")
		return SEQ_ERROR
	}
	if l.Len() == 0 {
		l.PushFront(node)
		return SEQ_DISCONTINUOUS
	}

	first := l.Front().Value.(*SeqSegment)
	last := l.Back().Value.(*SeqSegment)

	if last.seqNumber <= node.seqNumber { // 正常情况，对于同向payloadLen>0包，均连续
		if node.seqNumber > last.seqNumber+last.length { // 不连续, 添加新节点
			l.InsertAfter(node, l.Back())
			flag = SEQ_DISCONTINUOUS
		} else if node.seqNumber+node.length <= last.seqNumber+last.length { // 重传
			flag = SEQ_RETRANS
		} else { // 连续
			left = l.Back().Value.(*SeqSegment)
			if ok := p.isContinuousSeqSegment(left, nil, node); ok > 0 {
				flag = SEQ_CONTINUOUS
			} else {
				flag = SEQ_ERROR
				log.Debugf("node.lengthgth error, node:%v", node)
			}
		}
	} else if first.seqNumber <= node.seqNumber {
		for e = l.Front(); e != l.Back(); e = e.Next() {
			v := e.Value.(*SeqSegment)
			if node.seqNumber < v.seqNumber { // 查找node在list中的位置
				break
			}
		}
		left = e.Prev().Value.(*SeqSegment)
		right = e.Value.(*SeqSegment)
		log.Debugf("left:%v, right:%v", left, right)

		if node.seqNumber+node.length <= left.seqNumber+left.length { // 重传判断
			flag = SEQ_RETRANS
		} else if node.seqNumber > left.seqNumber+left.length && node.seqNumber+node.length < right.seqNumber { // 重传判断
			// 不连续，处于left, right之间
			l.InsertBefore(node, e)
			flag = SEQ_DISCONTINUOUS
		} else {
			if ok := p.isContinuousSeqSegment(left, right, node); ok > 0 {
				if ok == SEQ_NODE_BOTH_CONTINUOUS {
					l.Remove(e)
				}
				flag = SEQ_CONTINUOUS
			} else {
				flag = SEQ_ERROR
				log.Debugf("node:%v length error", node)
			}
		}
	} else { // 乱序 first.seqNumber > node.seqNumber
		if first.seqNumber > node.seqNumber+node.length { // new, 不连续
			l.InsertBefore(node, l.Front())
			flag = SEQ_DISCONTINUOUS
		} else { // new, but continue, 合并连续
			right = l.Front().Value.(*SeqSegment)
			if ok := p.isContinuousSeqSegment(nil, right, node); ok > 0 {
				flag = SEQ_CONTINUOUS
			} else {
				flag = SEQ_ERROR
				log.Debugf("node:%v length error", node)
			}
		}
	}

	return flag
}

// 在TCP_STATE_ESTABLISHED阶段更新数据
func (p *TcpSessionPeer) updateData(header *handler.MetaPacketHeader) {
	tcphdr := header.TcpData
	p.timestamp = time.Duration(header.Timestamp)
	p.payloadLen = uint32(header.PayloadLen)
	p.seq = tcphdr.Seq
	p.winSize = tcphdr.WinSize
	// winScale不能在这里更新p.winScale = tcphdr.WinScale
}

// 更新状态
func (p *TcpSessionPeer) updateState(state TcpConnState) {
	p.tcpState = state
}

func (p *TcpSessionPeer) String() string {
	var list string

	data := fmt.Sprintf("tcpState:%v, timestamp:%v, seq:%v, payloadLen:%v, winSize:%v"+
		"winScale:%v, canCalcRtt:%v, canCalcArt:%v",
		p.tcpState, p.timestamp, p.seq, p.payloadLen,
		p.winSize, p.winScale, p.canCalcRtt, p.canCalcArt)

	l := p.seqList
	if l == nil {
		return fmt.Sprintf("%s, seqList:nil", data)
	}

	length := l.Len()
	list = fmt.Sprintf("length:%v", length)
	if length > 0 {
		for e := l.Front(); e != nil; e = e.Next() {
			v := e.Value.(*SeqSegment)
			list = fmt.Sprintf("%s,{%v,%v}", list, v.seqNumber, v.length)
		}
	}

	return fmt.Sprintf("TcpSessionPeer: %s, seqList:[%s]", data, list)
}

func isAckPkt(header *handler.MetaPacketHeader) bool {
	tcpflag := header.TcpData.Flags
	payloadLen := header.PayloadLen
	if tcpflag == TCP_ACK && payloadLen == 0 {
		return true
	}

	return false
}

func calcTimeInterval(currentTime, lastTime time.Duration) time.Duration {
	interval := currentTime - lastTime
	if interval == 0 {
		interval = 10 * time.Microsecond
	}

	return interval
}

// 用第一个包,构建初始状态
func (f *FlowPerfCtrlInfo) firstPacket(header *handler.MetaPacketHeader) error {
	tcphdr := &header.TcpData
	client := &f.tcpSession[utils.Bool2Int(TCP_DIR_CLIENT)]
	server := &f.tcpSession[utils.Bool2Int(TCP_DIR_SERVER)]

	switch flag := tcphdr.Flags & (TCP_SYN | TCP_ACK); flag {
	case TCP_SYN: // SYN包
		if tcphdr.WinScale > 0 {
			client.winScale = WIN_SCALE_FLAG | uint8(utils.Min(WIN_SCALE_MAX, int(tcphdr.WinScale)))
		}
		client.tcpState = TCP_STATE_SYN_SENT
		// should regard package length as 1, but must client.payloadlen = 0
		client.assertSeqNumber(tcphdr, 1)

		server.tcpState = TCP_STATE_LISTEN
	case TCP_SYN | TCP_ACK: // SYN/ACK包
		// as NO SYN packet, do not calc winScale
		client.tcpState = TCP_STATE_SYN_RECV
		// should regard package length as 1, but must client.payloadlen = 0
		client.assertSeqNumber(tcphdr, 1)

		server.tcpState = TCP_STATE_SYN_SENT
	default: // 流的第一个包非(SYN或SYN/ACK)
		client.tcpState = TCP_STATE_ESTABLISHED
		if header.PayloadLen > 0 {
			client.assertSeqNumber(tcphdr, header.PayloadLen)
		}

		server.tcpState = TCP_STATE_ESTABLISHED
	}

	return nil
}

func (m *MetaFlowPerf) fsmListen(sameDir, oppositeDir *TcpSessionPeer, header *handler.MetaPacketHeader, direction bool) error {
	var err FlowPerfError

	tcphdr := &header.TcpData
	perfData := m.perfData

	stateOk := (oppositeDir.tcpState == TCP_STATE_SYN_SENT)
	flagOk := (header.TcpData.Flags == (TCP_SYN | TCP_ACK))
	ackOk := (oppositeDir.seq+1 == header.TcpData.Ack)
	log.Debugf("stateOk:%v,flagOk:%v,ackOk:%v", stateOk, flagOk, ackOk)
	if stateOk && flagOk && ackOk {
		// rttSyn1
		rtt := calcTimeInterval(header.Timestamp, oppositeDir.timestamp)
		perfData.calcRttSyn(rtt, direction)
		m.counter.validRttSynTimes += 1

		// update data
		if header.TcpData.WinScale > 0 {
			if oppositeDir.winScale&WIN_SCALE_FLAG == WIN_SCALE_FLAG {
				sameDir.winScale = WIN_SCALE_FLAG | uint8(utils.Min(int(WIN_SCALE_MAX), int(header.TcpData.WinScale)))
			}
		} else {
			oppositeDir.winScale = 0
		}

		sameDir.assertSeqNumber(tcphdr, 1)

		// update state
		sameDir.updateState(TCP_STATE_SYN_RECV)
		log.Debugf("perfCtrl:%v,%v,perfData:%v", m.ctrlInfo.tcpSession[0], m.ctrlInfo.tcpSession[1], perfData)
	} else {
		m.counter.invalidPktCnt += 1
		err = FlowPerfError{where: "",
			what: "invalid SYN/ACK packet"}
	}

	return err.returnErr()
}

func (m *MetaFlowPerf) fsmSynSent(sameDir, oppositeDir *TcpSessionPeer, header *handler.MetaPacketHeader, direction bool) error {
	var err FlowPerfError
	perfData := m.perfData
	tcphdr := &header.TcpData
	ackOk := (oppositeDir.seq+1 == tcphdr.Ack)
	isAckPkt := isAckPkt(header)

	if tcphdr.Flags == TCP_SYN && oppositeDir.tcpState == TCP_STATE_LISTEN { // 重传 SYN
		seqState := sameDir.assertSeqNumber(tcphdr, 1)
		if seqState == SEQ_RETRANS {
			perfData.calcRetransSyn(direction)
			m.counter.validSynRetransTimes += 1
		} else {
			m.counter.invalidPktCnt += 1
			err = FlowPerfError{where: "",
				what: "invalid retrans SYN packet"}
		}
	} else if ackOk && isAckPkt && oppositeDir.tcpState == TCP_STATE_SYN_RECV { // ACK
		// rttSyn0
		rtt := calcTimeInterval(header.Timestamp, oppositeDir.timestamp)
		perfData.calcRttSyn(rtt, direction)
		m.counter.validRttSynTimes += 1

		// update state
		sameDir.updateState(TCP_STATE_ESTABLISHED)
		oppositeDir.updateState(TCP_STATE_ESTABLISHED)
	} else {
		m.counter.unknownPktCnt += 1
		err = FlowPerfError{where: "", what: "unknown ACK packet"}
		log.Info("unknown ACK packet")
	}

	return err.returnErr()
}

func (m *MetaFlowPerf) fsmSynRecv(sameDir, oppositeDir *TcpSessionPeer, header *handler.MetaPacketHeader, direction bool) error {
	var err FlowPerfError
	perfData := m.perfData
	tcphdr := &header.TcpData
	if tcphdr.Flags == (TCP_SYN|TCP_ACK) && oppositeDir.tcpState == TCP_STATE_SYN_SENT {
		seqState := sameDir.assertSeqNumber(tcphdr, 1)
		if seqState == SEQ_RETRANS {
			perfData.calcRetransSyn(direction)
			m.counter.validSynRetransTimes += 1
		} else {
			m.counter.invalidPktCnt += 1
			err = FlowPerfError{where: "", what: "invalid retrans SYN/ACK packet"}
		}
	} else {
		m.counter.unknownPktCnt += 1
		err = FlowPerfError{where: "", what: "unknown retrans SYN/ACK packet"}
	}

	return err.returnErr()
}

// 同方向连续
// same.seq+len == opposite.seq
// 反方向连续
// same.Ack == oppositeDir.Seq + len
func (m *MetaFlowPerf) fsmEstablished(sameDir, oppositeDir *TcpSessionPeer, header *handler.MetaPacketHeader, direction bool) error {
	var err FlowPerfError
	perfData := m.perfData
	tcphdr := &header.TcpData

	log.Debugf("TCP_STATE_ESTABLISHED--tcp payloadLen:%v --", header.PayloadLen)
	if header.PayloadLen > 0 { // PSH/ACK(payloadLen>0)
		seqState := sameDir.assertSeqNumber(tcphdr, header.PayloadLen)
		switch seqState {
		case SEQ_RETRANS:
			// 重传数据包,认为ACK包不存在重传
			perfData.calcRetrans(direction)
			m.counter.validRetransTimes += 1
			oppositeDir.setRttPrecondition()
			sameDir.resetRttPrecondition()
		case SEQ_CONTINUOUS: // 非重传
			oppositeDir.setRttPrecondition()
			sameDir.resetRttPrecondition()

			// art--用连续的PSH/ACK(payloadLen>0)、ACK和PSH/ACK(payloadLen>0)计算服务端的art值，
			//     且ACK包的payloadLen为0
			seqContinusOk := (sameDir.seq == tcphdr.Seq) // 同方向，前一个ACK
			// 反方向，前一个PSH/ACK(payloadLen>0)
			ackOk := (tcphdr.Ack == oppositeDir.seq+oppositeDir.payloadLen)
			precondition := sameDir.getArtPrecondition()
			directionOk := (direction == TCP_DIR_SERVER)
			log.Debugf("art--seqContinusOk:%v, ackOk:%v, precondition:%v",
				seqContinusOk, ackOk, precondition)
			if seqContinusOk && ackOk && precondition && directionOk {
				art := calcTimeInterval(header.Timestamp, sameDir.timestamp)
				perfData.calcArt(art, direction)
				m.counter.validArtTimes += 1

				sameDir.resetArtPrecondition()
			}
		default:
			m.counter.unknownPktCnt += 1
			err = FlowPerfError{where: "", what: "seqAssert DISCONTIOUS or ERROR"}
			log.Debugf("seqAssert result:%v", seqState)
		}
	} else { // ACK, payloadLen == 0
		// rtt--用连续的PSH/ACK(payloadLen>0)和ACK计算从探针点到服务端的rtt值rtt_1，
		//	   且ACK包的payloadLen长度为0
		log.Debugf("----ACK, payloadLen == 0")
		ackOk := (oppositeDir.seq+oppositeDir.payloadLen == tcphdr.Ack)
		isAck := isAckPkt(header)
		if ackOk && isAck {
			if ok := sameDir.getRttPrecondition(); ok {
				rtt := calcTimeInterval(header.Timestamp, oppositeDir.timestamp)
				perfData.calcRtt(rtt, direction)
				m.counter.validRttTimes += 1

				sameDir.setArtPrecondition()
				sameDir.resetRttPrecondition()
				oppositeDir.resetRttPrecondition()
			}
		} else {
			m.counter.unknownPktCnt += 1
			err = FlowPerfError{where: "", what: "discontinuous ACK packet"}
			log.Debugf("=----discontinuous packet, ack:%v", tcphdr.Ack)
		}
	}

	winSize := tcphdr.WinSize << sameDir.winScale
	// winSize == 0 or zero window
	if winSize == 0 {
		perfData.calcZeroWnd(direction)
	}

	// PSH/URG
	if tcphdr.Flags&(TCP_PSH|TCP_URG) == (TCP_PSH | TCP_URG) {
		perfData.calcPshUrg(direction)
	}

	return err.returnErr()
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (m *MetaFlowPerf) reestablishFsm(sameDir, oppositeDir *TcpSessionPeer, header *handler.MetaPacketHeader, direction bool) uint32 {
	var err error
	stateOppst := oppositeDir.tcpState
	state := sameDir.tcpState

	log.Debugf("state:%v, stateOppst:%v", state, stateOppst)
	switch state {
	case TCP_STATE_CLOSED: // first packet
		if stateOppst == TCP_STATE_CLOSED {
			err = m.ctrlInfo.firstPacket(header)
		}
	case TCP_STATE_LISTEN: // SYN/ACK
		err = m.fsmListen(sameDir, oppositeDir, header, direction)
	case TCP_STATE_SYN_SENT: // ACK
		err = m.fsmSynSent(sameDir, oppositeDir, header, direction)
	case TCP_STATE_SYN_RECV: // 重传 SYN/ACK
		err = m.fsmSynRecv(sameDir, oppositeDir, header, direction)
	case TCP_STATE_ESTABLISHED: // PSH/ACK || ACK
		if header.TcpData.Flags&TCP_ACK > 0 {
			if err = m.fsmEstablished(sameDir, oppositeDir, header, direction); err != nil {
				sameDir.resetArtPrecondition()
				sameDir.resetRttPrecondition()
				oppositeDir.resetArtPrecondition()
				oppositeDir.resetRttPrecondition()
			}
		} else {
			m.counter.unknownPktCnt += 1
			log.Debugf("unknown packet")
		}
	default: // unlikely
		log.Debugf("unknown TCP_STATE: state(%v)", state)
	}

	if err != nil {
		log.Debug(err.Error())
	}

	return 0
}

// FIXME: art,rrt均值计算方法，需要增加影响因子
// 计算art值
func (f *FlowPerfDataInfo) calcArt(art time.Duration, direction bool) {
	if direction == TCP_DIR_SERVER {
		f.periodPerfStat.artCnt += 1
		f.periodPerfStat.artSum += art
		f.flowPerfStat.artCnt += 1
		f.flowPerfStat.artSum += art
	}
	log.Debugf("artCalc--art:%v, direction:%v", art, direction)
}

// 计算rtt值
func (f *FlowPerfDataInfo) calcRtt(rtt time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.periodPerfStat.rtt0Sum += rtt
		f.periodPerfStat.rtt0Cnt += 1
		f.flowPerfStat.rtt0Sum += rtt
		f.flowPerfStat.rtt0Cnt += 1
	} else {
		f.periodPerfStat.rtt1Sum += rtt
		f.periodPerfStat.rtt1Cnt += 1
		f.flowPerfStat.rtt1Sum += rtt
		f.flowPerfStat.rtt1Cnt += 1
	}

	log.Debugf("rttCalc--rtt:%v, direction:%v", rtt, direction)
}

// 计算rttSyn值
func (f *FlowPerfDataInfo) calcRttSyn(rtt time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.flowPerfStat.rttSyn0 += rtt
		f.flowPerfStat.rtt0Sum += rtt
		f.flowPerfStat.rtt0Cnt += 1
	} else {
		f.flowPerfStat.rttSyn1 += rtt
		f.flowPerfStat.rtt1Sum += rtt
		f.flowPerfStat.rtt1Cnt += 1
	}

	log.Debugf("rttSynCalc--rttsyn:%V, direction:%v", rtt, direction)
}

// 计算连接建立syn retrans值
func (f *FlowPerfDataInfo) calcRetransSyn(direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.periodPerfStat.retransSyn0 += 1
		f.flowPerfStat.retransSyn0 += 1
	} else {
		f.periodPerfStat.retransSyn1 += 1
		f.flowPerfStat.retransSyn1 += 1
	}

	log.Debugf("retransSynCalc--direction:%v", direction)
}

// 计算retrans值
func (f *FlowPerfDataInfo) calcRetrans(direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.periodPerfStat.retrans0 += 1
		f.flowPerfStat.retrans0 += 1
	} else {
		f.periodPerfStat.retrans1 += 1
		f.flowPerfStat.retrans1 += 1
	}

	log.Debugf("retransCalc--direction:%v", direction)
}

// 计算zero window包数量
func (f *FlowPerfDataInfo) calcZeroWnd(direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.periodPerfStat.zeroWndCnt0 += 1
		f.flowPerfStat.zeroWndCnt0 += 1
	} else {
		f.periodPerfStat.zeroWndCnt1 += 1
		f.flowPerfStat.zeroWndCnt1 += 1
	}

	log.Debugf("zeroWndCalc--direction:%v", direction)
}

// 计算PSH/URG包数量
func (f *FlowPerfDataInfo) calcPshUrg(direction bool) {
	if direction == TCP_DIR_CLIENT {
		f.periodPerfStat.pshUrgCnt0 += 1
		f.flowPerfStat.pshUrgCnt0 += 1

	} else {
		f.periodPerfStat.pshUrgCnt1 += 1
		f.flowPerfStat.pshUrgCnt1 += 1
	}

	log.Debugf("pshUrgCalc--direction:%v", direction)
}

// check if tcphdr is valid
func checkTcpFlags(tcpFlags uint8) bool {
	log.Debugf("tcpflag:%x", tcpFlags)
	if tcpFlags&TCP_SYN != 0 {
		if tcpFlags&(TCP_FIN|TCP_RST) != 0 {
			return false
		}
	} else {
		if tcpFlags&(TCP_ACK|TCP_RST) == 0 {
			return false
		}
	}

	if tcpFlags&TCP_ACK == 0 {
		if tcpFlags&(TCP_PSH|TCP_FIN|TCP_URG) != 0 {
			return false
		}
	}

	// flow perf do not take care
	if tcpFlags&(TCP_FIN|TCP_RST) > 0 {
		return false
	}

	return true
}

func NewMetaFlowPerf() *MetaFlowPerf {
	client := TcpSessionPeer{seqList: list.New()}
	server := TcpSessionPeer{seqList: list.New()}

	// 初始化MetaFlowPerf结构
	meta := &MetaFlowPerf{
		ctrlInfo: &FlowPerfCtrlInfo{
			tcpSession: TcpConnSession{client, server},
		},
		perfData: &FlowPerfDataInfo{
			reportPerfStat: &TcpPerfStat{},
			periodPerfStat: &MetaPerfStat{},
			flowPerfStat:   &MetaPerfStat{},
		},
		counter: &FlowPerfCounter{},
	}
	stats.RegisterCountable(FP_NAME, stats.EMPTY_TAG, meta)

	return meta
}

// 异常flag判断，方向识别，payloadLen计算等
// 去除功能不相关报文
func (m *MetaFlowPerf) preprocess(header *handler.MetaPacketHeader) bool {
	if ok := checkTcpFlags(header.TcpData.Flags); !ok {
		m.counter.invalidPktCnt += 1

		log.Debugf("invalid packet, err tcpflag:%x", header.TcpData.Flags)
		return false
	}

	return true
}

// update flow performace quantify state and data
func (m *MetaFlowPerf) Update(header *handler.MetaPacketHeader, direction bool) error {
	var err FlowPerfError
	var sameDir, oppositeDir *TcpSessionPeer

	if m.ctrlInfo == nil || m.perfData == nil || m.counter == nil {
		err = FlowPerfError{what: "receiver(*MetaFlowPerf) error"}
		log.Debugf("error input: ctrlInfo == nil || perfData == nil || counter == nil")
		return err
	}

	if direction == TCP_DIR_CLIENT {
		sameDir = &m.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_CLIENT)]
		oppositeDir = &m.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_SERVER)]
	} else {
		sameDir = &m.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_SERVER)]
		oppositeDir = &m.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_CLIENT)]
	}

	if valid := m.preprocess(header); valid {
		if time.Duration(header.Timestamp) < sameDir.timestamp || time.Duration(header.Timestamp) < oppositeDir.timestamp {
			m.counter.invalidPktCnt += 1
			log.Debugf("packet timestamp error, same last:%v, opposite last:%v, packet:%v",
				sameDir.timestamp, oppositeDir.timestamp, header.Timestamp)
			err = FlowPerfError{what: "packet timestamp error"}
			return err
		}
		// 根据pkthdr, direction重建状态机
		m.reestablishFsm(sameDir, oppositeDir, header, direction)
		log.Debugf("flow data:%v", m.perfData)

		sameDir.updateData(header)
	} else { // art, rtt控制字段置位
		sameDir.resetRttPrecondition()
		sameDir.resetArtPrecondition()
		oppositeDir.resetArtPrecondition()
		oppositeDir.resetRttPrecondition()
	}

	return nil
}

func (m *MetaFlowPerf) Report() *TcpPerfStat {
	if m.perfData != nil {
		report := &TcpPerfStat{}
		m.perfData.calcReportFlowPerfStat()

		m.perfData.reportPerfStat, report = report, m.perfData.reportPerfStat

		m.perfData.resetPeriodPerfStat()
		return report
	}

	log.Debugf("m.perfData == nil")

	return nil
}

func (f *FlowPerfDataInfo) calcReportFlowPerfStat() {
	report := f.reportPerfStat
	period := f.periodPerfStat
	flow := f.flowPerfStat

	if period.artCnt > 0 {
		report.ARTAvg = period.artSum / time.Duration(period.artCnt)
	}
	report.RTTSyn = flow.rttSyn0 + flow.rttSyn1

	if flow.rtt0Cnt > 0 {
		report.RTTAvg += flow.rtt0Sum / time.Duration(flow.rtt0Cnt)
	}
	if flow.rtt1Cnt > 0 {
		report.RTTAvg += flow.rtt1Sum / time.Duration(flow.rtt1Cnt)
	}

	if period.rtt0Cnt == 0 {
		period.rtt0Cnt = flow.rtt0Cnt
		period.rtt0Sum = flow.rtt0Sum
	}
	if period.rtt0Cnt > 0 {
		report.RTT += period.rtt0Sum / time.Duration(period.rtt0Cnt)
	}
	if period.rtt1Cnt == 0 {
		period.rtt1Cnt = flow.rtt1Cnt
		period.rtt1Sum = flow.rtt1Sum
	}
	if period.rtt1Cnt > 0 {
		report.RTT += period.rtt1Sum / time.Duration(period.rtt1Cnt)
	}

	report.SynRetransCnt0 = uint64(period.retransSyn0)
	report.SynRetransCnt1 = uint64(period.retransSyn1)

	report.RetransCnt0 = uint64(period.retrans0)
	report.RetransCnt1 = uint64(period.retrans1)
	report.TotalRetransCnt = uint64(flow.retrans0 + flow.retrans1)

	report.ZeroWndCnt0 = uint64(period.zeroWndCnt0)
	report.ZeroWndCnt1 = uint64(period.zeroWndCnt1)
	report.TotalZeroWndCnt = uint64(flow.zeroWndCnt1 + flow.zeroWndCnt1)

	report.PshUrgCnt0 = uint64(period.pshUrgCnt0)
	report.PshUrgCnt1 = uint64(period.pshUrgCnt1)
	report.TotalPshUrgCnt = uint64(flow.pshUrgCnt0 + flow.pshUrgCnt1)
}

func (f *FlowPerfDataInfo) resetPeriodPerfStat() {
	f.periodPerfStat = &MetaPerfStat{}
}

func reflectFormat(valueVar interface{}) string {
	var formatStr string
	typeof := reflect.TypeOf(valueVar)
	valueof := reflect.ValueOf(valueVar)
	for i := 0; i < typeof.NumField(); i++ {
		formatStr += fmt.Sprintf("\t%v: %v\n", typeof.Field(i).Name, valueof.Field(i))
	}

	return formatStr
}

func (f *FlowPerfDataInfo) String() string {
	var reportStr string
	report := f.reportPerfStat
	if report != nil {
		reportStr = reflectFormat(*report)
	} else {
		reportStr = "nil"
	}

	return fmt.Sprintf("\nreportPerfStat:%v, \nperiodPerfStat:%v, \nflowPerfStat:%v",
		reportStr, f.periodPerfStat, f.flowPerfStat)
}

func (f *MetaPerfStat) String() string {
	return reflectFormat(*f)
}

// implement stats/GetCounter interface
func (m *MetaFlowPerf) GetCounter() interface{} {
	c := &FlowPerfCounter{}
	c, m.counter = m.counter, c

	return c
}

type FlowPerfError struct {
	when  time.Time
	where string
	what  string
}

func (e FlowPerfError) Error() string {
	_, _, line, ok := runtime.Caller(1)
	if !ok {
		line = -1
	}

	if len(e.what) > 0 {
		return fmt.Sprintf("(%v)-[%v-%v]: %v", e.when.String(), e.where, line, e.what)
	}

	return ""
}

func (e FlowPerfError) returnErr() error {
	if len(e.what) > 0 {
		return e
	}
	return nil
}
