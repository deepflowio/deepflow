package flowgenerator

import (
	"container/list"
	"fmt"
	"reflect"
	"runtime"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet/utils"
)

type ContinuousFlag uint8
type TcpConnSession [2]TcpSessionPeer
type PacketSeqTypeInSeqList uint8

const (
	FP_NAME = "flowperf"
)

const (
	TCP_DIR_CLIENT bool = false
	TCP_DIR_SERVER      = true
)

const (
	SEQ_NODE_DISCONTINUOUS   ContinuousFlag = 0
	SEQ_NODE_LEFT_CONTINUOUS                = 1 << iota
	SEQ_NODE_RIGHT_CONTINUOUS
	SEQ_NODE_BOTH_CONTINUOUS = SEQ_NODE_LEFT_CONTINUOUS | SEQ_NODE_RIGHT_CONTINUOUS
)

const (
	SEQ_ERROR PacketSeqTypeInSeqList = iota
	SEQ_CONTINUOUS
	SEQ_DISCONTINUOUS
	SEQ_RETRANS
	SEQ_NOT_CARE
)

const (
	WIN_SCALE_MAX     = 14
	WIN_SCALE_MASK    = 0x0f
	WIN_SCALE_FLAG    = 0x80
	WIN_SCALE_UNKNOWN = 0x40
)

const SEQ_LIST_MAX_LEN = 16

type SeqSegment struct { // 避免乱序，识别重传
	seqNumber uint32
	length    uint32
}

type TcpSessionPeer struct {
	seqList *list.List // 升序链表, 内容为SeqSegment

	seqThreshold  uint32 // fast SynRetrans Check
	isAckReceived bool   // AckRetrans check
	isSynReceived bool

	flowState  FlowState
	timestamp  time.Duration
	seq        uint32
	payloadLen uint32
	winSize    uint16
	winScale   uint8

	isAckPacket bool
	canCalcRtt  bool
	canCalcArt  bool
}

type FlowPerfCtrlInfo struct {
	tcpSession TcpConnSession
}

// art---Application Response Time
// 现有3个连续包PSH/ACK--ACK--PSH/ACK,其中第一个包是client端的请求包，
// 后2个包是server端的应答包，art表示后2个包之间的时间间隔
type MetaPerfStats struct {
	art0Count, art1Count, rtt0Count, rtt1Count uint32
	art0Sum, art1Sum, rtt0Sum, rtt1Sum         time.Duration
	rttSyn0, rttSyn1                           time.Duration

	retrans0, retrans1       uint32
	retransSyn0, retransSyn1 uint32

	pshUrgCount0, pshUrgCount1   uint32
	zeroWinCount0, zeroWinCount1 uint32
}

type FlowPerfDataInfo struct {
	reportPerfStats *TcpPerfStats // OUT
	periodPerfStats *MetaPerfStats
	flowPerfStats   *MetaPerfStats
}

type FlowPerfCounter struct {
	validRttSynTimes     uint32 `statsd:"rtt_syn_times"`     // Flow中某个满足rttSyn计算的地方计数加1
	validRttTimes        uint32 `statsd:"rtt_times"`         // Flow中某个满足rtt计算的地方计数加1
	validArtTimes        uint32 `statsd:"art_times"`         // Flow中某个满足art计算的地方计数加1
	validRetransTimes    uint32 `statsd:"retrans_times"`     // Flow中某个Packet发生多次重传计数加1
	validSynRetransTimes uint32 `statsd:"syn_retrans_times"` // Flow中在连接建立阶段，某个Packet发生多次重传计数加1
	invalidPacketCount   uint32 `statsd:"invalid_packet"`    // Flow中某个识别为异常包的地方计数加1
	unknownPacketCount   uint32 `statsd:"unknown_packet"`    // Flow中某个识别为unknown包的地方计数加1
}

type FlowInfo struct {
	FlowID uint64
	FlowState
	Direction         bool
	TotalPacketCount0 uint64
	TotalPacketCount1 uint64
	ArrTime0Last      time.Duration
	ArrTime1Last      time.Duration
	TcpFlags0         uint16
	TcpFlags1         uint16
}

type MetaFlowPerf struct {
	ctrlInfo *FlowPerfCtrlInfo
	perfData *FlowPerfDataInfo
	counter  *FlowPerfCounter // OUT
}

func (p *TcpSessionPeer) setArtPrecondition() {
	p.canCalcArt = true
}

func (p *TcpSessionPeer) resetArtPrecondition() {
	p.canCalcArt = false
}

func (p *TcpSessionPeer) setRttPrecondition() {
	p.canCalcRtt = true
}

func (p *TcpSessionPeer) resetRttPrecondition() {
	p.canCalcRtt = false
}

func (p *TcpSessionPeer) getArtPrecondition() bool {
	return p.canCalcArt
}

func (p *TcpSessionPeer) getRttPrecondition() bool {
	return p.canCalcRtt
}

// 反方向连续回复包 same.Ack == oppositeDirection.Seq + len
func (p *TcpSessionPeer) isReplyPacket(header *MetaPacket) bool {
	return p.seq+p.payloadLen == header.TcpData.Ack
}

// 同方向连续包 same.seq+len == opposite.seq
func (p *TcpSessionPeer) isNextPacket(header *MetaPacket) bool {
	return p.seq+p.payloadLen == header.TcpData.Seq
}

func isContinuousSeqSegment(left, right, node *SeqSegment, flowInfo *FlowInfo) ContinuousFlag {
	flag := SEQ_NODE_DISCONTINUOUS

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

func (p *TcpSessionPeer) mergeSeqListNode() {
	if p.seqList.Len() < SEQ_LIST_MAX_LEN {
		return
	}

	first := p.seqList.Front().Value.(*SeqSegment)
	second := p.seqList.Front().Next().Value.(*SeqSegment)
	second.length = second.seqNumber - first.seqNumber + second.length
	second.seqNumber = first.seqNumber

	p.seqList.Remove(p.seqList.Front())
}

func isRetransSeqSegment(left, node *SeqSegment) bool {
	if left == nil {
		return false
	}

	if node.seqNumber >= left.seqNumber && left.seqNumber+left.length >= node.seqNumber+node.length {
		return true
	}

	return false
}

func isErrorSeqSegment(left, right, node *SeqSegment) bool {
	if left != nil &&
		node.seqNumber < left.seqNumber+left.length &&
		node.seqNumber+node.length > left.seqNumber+left.length {
		return true
	}

	if right != nil && node.seqNumber+node.length > right.seqNumber {
		return true
	}

	return false
}

// 根据seqNumber判断包重传,连续,不连续
// 合并连续seqNumber
// 不连续则添加新节点, 构建升序链表
func (p *TcpSessionPeer) assertSeqNumber(tcpHeader *MetaPacketTcpHeader, payloadLen uint16, flowInfo *FlowInfo) PacketSeqTypeInSeqList {
	var flag PacketSeqTypeInSeqList
	var left, right *SeqSegment
	var rightElement, currentElement *list.Element

	if payloadLen == 0 {
		return SEQ_NOT_CARE
	}

	node := &SeqSegment{seqNumber: tcpHeader.Seq, length: uint32(payloadLen)}
	log.Debugf("node: %v", node)

	l := p.seqList
	if l == nil {
		log.Errorf("seqNumber list is nil, seqNumber data have lost")
		return SEQ_ERROR
	}
	if l.Len() == 0 {
		l.PushFront(node)
		return SEQ_NOT_CARE
	}

	// 从后往前查找
	for rightElement, currentElement = nil, l.Back(); currentElement != nil; rightElement, currentElement = currentElement, currentElement.Prev() {
		left = currentElement.Value.(*SeqSegment)
		if node.seqNumber >= left.seqNumber { // 查找node在list中的位置
			break
		}
	}

	if currentElement == nil {
		left = nil
	}
	if rightElement == nil {
		right = nil
	} else {
		right = rightElement.Value.(*SeqSegment)
	}

	if e := isErrorSeqSegment(left, right, node); e {
		flag = SEQ_ERROR
	} else if r := isRetransSeqSegment(left, node); r {
		flag = SEQ_RETRANS
	} else {
		if c := isContinuousSeqSegment(left, right, node, flowInfo); c == SEQ_NODE_DISCONTINUOUS {
			if rightElement == nil {
				l.InsertAfter(node, currentElement)
			} else {
				l.InsertBefore(node, rightElement)
			}
		} else if c == SEQ_NODE_BOTH_CONTINUOUS {
			left.length = left.length - node.length + right.length
			l.Remove(rightElement)
		}
		flag = SEQ_NOT_CARE
	}

	if p.seqList.Len() >= SEQ_LIST_MAX_LEN {
		p.mergeSeqListNode()
	}

	return flag
}

// 在TCP_STATE_ESTABLISHED阶段更新数据
func (p *TcpSessionPeer) updateData(header *MetaPacket) {
	tcpHeader := header.TcpData
	p.timestamp = time.Duration(header.Timestamp)
	p.payloadLen = uint32(header.PayloadLen)
	if tcpHeader.Flags&TCP_SYN > 0 {
		p.payloadLen = 1
	}
	p.seq = tcpHeader.Seq
	p.winSize = tcpHeader.WinSize
	// winScale不能在这里更新p.winScale = tcpHeader.WinScale
}

// 更新状态
func (p *TcpSessionPeer) updateState(state FlowState) {
	p.flowState = state
}

func (p *TcpSessionPeer) String() string {
	var list string

	data := fmt.Sprintf("tcpState:%v, timestamp:%v, seq:%v, payloadLen:%v, winSize:%v"+
		"winScale:%v, canCalcRtt:%v, canCalcArt:%v",
		p.flowState, p.timestamp, p.seq, p.payloadLen,
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

func isSynPacket(header *MetaPacket) bool {
	tcpFlag := header.TcpData.Flags & TCP_FLAG_MASK

	return tcpFlag == TCP_SYN
}

func isSynAckPacket(header *MetaPacket) bool {
	tcpFlag := header.TcpData.Flags & TCP_FLAG_MASK
	payloadLen := header.PayloadLen

	return tcpFlag == (TCP_SYN|TCP_ACK) && payloadLen == 0
}

// ACK, payloadLen == 0
func isAckPacket(header *MetaPacket) bool {
	tcpFlag := header.TcpData.Flags & TCP_FLAG_MASK
	payloadLen := header.PayloadLen

	return tcpFlag == TCP_ACK && payloadLen == 0
}

func isPshAckPacket(header *MetaPacket) bool {
	tcpFlag := header.TcpData.Flags & TCP_FLAG_MASK
	payloadLen := header.PayloadLen

	return tcpFlag&(TCP_ACK|TCP_PSH) > 0 && payloadLen > 0
}

func calcTimeInterval(currentTime, lastTime time.Duration) time.Duration {
	return currentTime - lastTime
}

// 判断是否重传或错误
func (p *MetaFlowPerf) isInvalidRetransPacket(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flowInfo *FlowInfo) bool {
	isInvalid := false

	payloadLen := header.PayloadLen
	if isSynPacket(header) { // SYN包
		if sameDirection.seqThreshold == 0 {
			sameDirection.seqThreshold = header.TcpData.Seq + 1
		} else {
			if sameDirection.isSynReceived {
				// fixme when only syn/ack --
				p.perfData.calcRetransSyn(flowInfo.Direction)
				p.counter.validSynRetransTimes += 1
			} else {
				sameDirection.isSynReceived = true
			}
		}

		return isInvalid
	}

	if isSynAckPacket(header) { // SYN包
		if sameDirection.seqThreshold == 0 {
			sameDirection.seqThreshold = header.TcpData.Seq + 1
			if oppositeDirection.seqThreshold == 0 {
				oppositeDirection.seqThreshold = header.TcpData.Ack
			}
		} else {
			p.perfData.calcRetransSyn(flowInfo.Direction)
			p.counter.validSynRetransTimes += 1
		}

		return isInvalid
	}

	if isAckPacket(header) {
		if header.TcpData.Seq == sameDirection.seqThreshold &&
			header.TcpData.Ack == oppositeDirection.seqThreshold {
			if sameDirection.isAckReceived == false {
				sameDirection.isAckReceived = true
			} else {
				p.perfData.calcRetransSyn(flowInfo.Direction)
				p.counter.validSynRetransTimes += 1
			}
		}

		return isInvalid
	}

	r := sameDirection.assertSeqNumber(header.TcpData, payloadLen, flowInfo)
	if r == SEQ_RETRANS {
		// established retrans
		p.perfData.calcRetrans(flowInfo.Direction)
		p.counter.validRetransTimes += 1
	} else if r == SEQ_ERROR {
		isInvalid = true
		p.counter.invalidPacketCount += 1
	}

	return isInvalid
}

func (p *MetaFlowPerf) whenFlowOpening(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flowInfo *FlowInfo) bool {
	isOpeningPkt := false

	if sameDirection.getRttPrecondition() {
		if ((isAckPacket(header) && sameDirection.seqThreshold == header.TcpData.Seq) || isSynAckPacket(header)) && oppositeDirection.isReplyPacket(header) {
			if rttSyn := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); rttSyn > 0 {
				p.perfData.calcRttSyn(rttSyn, flowInfo.Direction)
				p.counter.validRttSynTimes += 1
			}
			isOpeningPkt = true
		}
	}

	if isSynPacket(header) || isSynAckPacket(header) {
		if header.TcpData.WinScale > 0 {
			sameDirection.winScale = WIN_SCALE_FLAG | uint8(utils.Min(int(WIN_SCALE_MAX), int(header.TcpData.WinScale)))
		}

		oppositeDirection.setRttPrecondition()
		sameDirection.resetRttPrecondition()

		isOpeningPkt = true
	}

	return isOpeningPkt
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (p *MetaFlowPerf) whenFlowEstablished(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flowInfo *FlowInfo) {
	// rtt--用连续的PSH/ACK(payloadLen>0)和反向ACK(payloadLen==0)计算rtt值
	if sameDirection.getRttPrecondition() {
		if isAckPacket(header) && oppositeDirection.isReplyPacket(header) {
			if rtt := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); rtt > 0 {
				p.perfData.calcRtt(rtt, flowInfo.Direction)
				p.counter.validRttTimes += 1
			}
		}
	}

	// art--用连续的PSH/ACK(payloadLen>0)和ACK(payloadLen==0)[可选]、PSH/ACK(payloadLen>0)计算art值，
	if sameDirection.getArtPrecondition() {
		if isPshAckPacket(header) && sameDirection.isNextPacket(header) {
			if art := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); art > 0 {
				p.perfData.calcArt(art, flowInfo.Direction)
				p.counter.validArtTimes += 1
			}
		}
	}

	if isAckPacket(header) {
		sameDirection.resetRttPrecondition()

		oppositeDirection.resetRttPrecondition()
		oppositeDirection.resetArtPrecondition()
	}

	if isPshAckPacket(header) {
		sameDirection.resetArtPrecondition()
		sameDirection.resetRttPrecondition()

		oppositeDirection.setRttPrecondition()
		oppositeDirection.setArtPrecondition()
	}

	//zerowin, pshUrgCount0
	winSize := header.TcpData.WinSize
	if sameDirection.winScale&oppositeDirection.winScale&WIN_SCALE_FLAG > 0 {
		winSize = header.TcpData.WinSize << sameDirection.winScale
	}
	// winSize == 0 or zero window
	if winSize == 0 {
		p.perfData.calcZeroWin(flowInfo.Direction)
	}

	// PSH/URG
	if header.TcpData.Flags&TCP_FLAG_MASK == (TCP_ACK | TCP_PSH | TCP_URG) {
		p.perfData.calcPshUrg(flowInfo.Direction)
	}
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (p *MetaFlowPerf) update(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flow *FlowInfo) {
	// check /isRetrans, not_care, error, continuous
	if p.isInvalidRetransPacket(sameDirection, oppositeDirection, header, flow) {
		p.ctrlInfo.tcpSession[0].resetRttPrecondition()
		p.ctrlInfo.tcpSession[0].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetRttPrecondition()
		return
	}

	// 计算RTT, ART
	if !p.whenFlowOpening(sameDirection, oppositeDirection, header, flow) {
		p.whenFlowEstablished(sameDirection, oppositeDirection, header, flow)
	}
}

// FIXME: art,rrt均值计算方法，需要增加影响因子
// 计算art值
func (i *FlowPerfDataInfo) calcArt(art time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.art0Count += 1
		i.periodPerfStats.art0Sum += art
		i.flowPerfStats.art0Count += 1
		i.flowPerfStats.art0Sum += art
	} else {
		i.periodPerfStats.art1Count += 1
		i.periodPerfStats.art1Sum += art
		i.flowPerfStats.art1Count += 1
		i.flowPerfStats.art1Sum += art
	}

	log.Debugf("artCalc--art:%v, direction:%v", art, direction)
}

// 计算rtt值
func (i *FlowPerfDataInfo) calcRtt(rtt time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.rtt0Sum += rtt
		i.periodPerfStats.rtt0Count += 1
		i.flowPerfStats.rtt0Sum += rtt
		i.flowPerfStats.rtt0Count += 1
	} else {
		i.periodPerfStats.rtt1Sum += rtt
		i.periodPerfStats.rtt1Count += 1
		i.flowPerfStats.rtt1Sum += rtt
		i.flowPerfStats.rtt1Count += 1
	}

	log.Debugf("rttCalc--rtt:%v, direction:%v", rtt, direction)
}

// 计算rttSyn值
func (i *FlowPerfDataInfo) calcRttSyn(rtt time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.flowPerfStats.rttSyn0 += rtt
		i.flowPerfStats.rtt0Sum += rtt
		i.flowPerfStats.rtt0Count += 1
	} else {
		i.flowPerfStats.rttSyn1 += rtt
		i.flowPerfStats.rtt1Sum += rtt
		i.flowPerfStats.rtt1Count += 1
	}

	log.Debugf("rttSynCalc--rttsyn:%V, direction:%v", rtt, direction)
}

// 计算连接建立syn retrans值
func (i *FlowPerfDataInfo) calcRetransSyn(direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.retransSyn0 += 1
		i.flowPerfStats.retransSyn0 += 1
	} else {
		i.periodPerfStats.retransSyn1 += 1
		i.flowPerfStats.retransSyn1 += 1
	}

	log.Debugf("retransSynCalc--direction:%v", direction)
}

// 计算retrans值
func (i *FlowPerfDataInfo) calcRetrans(direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.retrans0 += 1
		i.flowPerfStats.retrans0 += 1
	} else {
		i.periodPerfStats.retrans1 += 1
		i.flowPerfStats.retrans1 += 1
	}

	log.Debugf("retransCalc--direction:%v", direction)
}

// 计算zero window包数量
func (i *FlowPerfDataInfo) calcZeroWin(direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.zeroWinCount0 += 1
		i.flowPerfStats.zeroWinCount0 += 1
	} else {
		i.periodPerfStats.zeroWinCount1 += 1
		i.flowPerfStats.zeroWinCount1 += 1
	}

	log.Debugf("zeroWinCalc--direction:%v", direction)
}

// 计算PSH/URG包数量
func (i *FlowPerfDataInfo) calcPshUrg(direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.periodPerfStats.pshUrgCount0 += 1
		i.flowPerfStats.pshUrgCount0 += 1

	} else {
		i.periodPerfStats.pshUrgCount1 += 1
		i.flowPerfStats.pshUrgCount1 += 1
	}

	log.Debugf("pshUrgCalc--direction:%v", direction)
}

// check if tcpHeader is valid
func checkTcpFlags(tcpFlags uint8) bool {
	log.Debugf("tcpFlag:%x", tcpFlags)
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
			reportPerfStats: &TcpPerfStats{},
			periodPerfStats: &MetaPerfStats{},
			flowPerfStats:   &MetaPerfStats{},
		},
		counter: &FlowPerfCounter{},
	}
	stats.RegisterCountable(FP_NAME, stats.EMPTY_TAG, meta)
	runtime.SetFinalizer(meta, func(m *MetaFlowPerf) { m.Close() })

	return meta
}

func (m *MetaFlowPerf) Close() {
	stats.DeregisterCountable(m)
}

// 异常flag判断，方向识别，payloadLen计算等
// 去除功能不相关报文
func (p *MetaFlowPerf) preprocess(header *MetaPacket, flowInfo *FlowInfo) bool {
	if ok := checkTcpFlags(header.TcpData.Flags & TCP_FLAG_MASK); !ok {
		p.counter.invalidPacketCount += 1

		log.Debugf("invalid packet, err tcpFlag:%x", header.TcpData.Flags&TCP_FLAG_MASK)
		return false
	}

	return true
}

// update flow performace quantify state and data
func (p *MetaFlowPerf) Update(header *MetaPacket, flowInfo *FlowInfo) error {
	var err FlowPerfError
	var sameDirection, oppositeDirection *TcpSessionPeer

	if header == nil || flowInfo == nil {
		err = FlowPerfError{what: "packet header or flow info is nil"}
		return err
	}

	if valid := p.preprocess(header, flowInfo); valid {
		if flowInfo.Direction == TCP_DIR_CLIENT {
			sameDirection = &p.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_CLIENT)]
			oppositeDirection = &p.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_SERVER)]
		} else {
			sameDirection = &p.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_SERVER)]
			oppositeDirection = &p.ctrlInfo.tcpSession[utils.Bool2Int(TCP_DIR_CLIENT)]
		}

		if time.Duration(header.Timestamp) < sameDirection.timestamp || time.Duration(header.Timestamp) < oppositeDirection.timestamp {
			p.counter.invalidPacketCount += 1
			log.Debugf("packet timestamp error, same last:%v, opposite last:%v, packet:%v",
				sameDirection.timestamp, oppositeDirection.timestamp, header.Timestamp)
			err = FlowPerfError{what: "packet timestamp error"}
			return err
		}

		// 根据packetHeader, direction重建状态机
		//p.reestablishFsm(sameDirection, oppositeDirection, header, flow)
		p.update(sameDirection, oppositeDirection, header, flowInfo)
		log.Debugf("flow info:%v\n, packet header:%v,\n perfData data:%v\n", flowInfo, header, p.perfData)

		// 更新包数据
		sameDirection.updateData(header)
	} else { // art, rtt控制字段置位
		p.ctrlInfo.tcpSession[0].resetRttPrecondition()
		p.ctrlInfo.tcpSession[0].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetRttPrecondition()
	}

	return nil
}

func (p *MetaFlowPerf) Report(reverse bool) *TcpPerfStats {
	if p.perfData != nil {
		report := &TcpPerfStats{}
		p.perfData.calcReportFlowPerfStats(reverse)

		if reverse == true {
			p.perfData.exchangeReportFlowPerfStats()
		}

		p.perfData.reportPerfStats, report = report, p.perfData.reportPerfStats

		p.perfData.resetPeriodPerfStats()
		return report
	}

	log.Debugf("p.perfData == nil")

	return nil
}

func (i *FlowPerfDataInfo) exchangeReportFlowPerfStats() {
	report := i.reportPerfStats

	report.RetransCount0, report.RetransCount1 = report.RetransCount1, report.RetransCount0
	report.SynRetransCount0, report.SynRetransCount1 = report.SynRetransCount1, report.SynRetransCount0

	report.ZeroWinCount0, report.ZeroWinCount1 = report.ZeroWinCount1, report.ZeroWinCount0
	report.PshUrgCount0, report.PshUrgCount1 = report.PshUrgCount1, report.PshUrgCount0
}

func (i *FlowPerfDataInfo) calcReportFlowPerfStats(reverse bool) {
	report := i.reportPerfStats
	period := i.periodPerfStats
	flow := i.flowPerfStats

	if reverse == true {
		if period.art1Count > 0 {
			report.ARTAvg = period.art1Sum / time.Duration(period.art1Count)
		}
	} else {
		if period.art0Count > 0 {
			report.ARTAvg = period.art0Sum / time.Duration(period.art0Count)
		}
	}

	report.RTTSyn = flow.rttSyn0 + flow.rttSyn1

	if flow.rtt0Count > 0 {
		report.RTTAvg += flow.rtt0Sum / time.Duration(flow.rtt0Count)
	}
	if flow.rtt1Count > 0 {
		report.RTTAvg += flow.rtt1Sum / time.Duration(flow.rtt1Count)
	}

	if period.rtt0Count == 0 {
		period.rtt0Count = flow.rtt0Count
		period.rtt0Sum = flow.rtt0Sum
	}
	if period.rtt0Count > 0 {
		report.RTT += period.rtt0Sum / time.Duration(period.rtt0Count)
	}
	if period.rtt1Count == 0 {
		period.rtt1Count = flow.rtt1Count
		period.rtt1Sum = flow.rtt1Sum
	}
	if period.rtt1Count > 0 {
		report.RTT += period.rtt1Sum / time.Duration(period.rtt1Count)
	}

	report.SynRetransCount0 = period.retransSyn0
	report.SynRetransCount1 = period.retransSyn1

	report.RetransCount0 = period.retrans0
	report.RetransCount1 = period.retrans1
	report.TotalRetransCount = flow.retrans0 + flow.retrans1

	report.ZeroWinCount0 = period.zeroWinCount0
	report.ZeroWinCount1 = period.zeroWinCount1
	report.TotalZeroWinCount = flow.zeroWinCount0 + flow.zeroWinCount1

	report.PshUrgCount0 = period.pshUrgCount0
	report.PshUrgCount1 = period.pshUrgCount1
	report.TotalPshUrgCount = flow.pshUrgCount0 + flow.pshUrgCount1
}

func (i *FlowPerfDataInfo) resetPeriodPerfStats() {
	i.periodPerfStats = &MetaPerfStats{}
}

func reflectFormat(valueVar interface{}) string {
	var formatStr string
	typeof := reflect.TypeOf(valueVar)
	valueof := reflect.ValueOf(valueVar)
	for i := 0; i < typeof.NumField(); i++ {
		formatStr += fmt.Sprintf("{%v: %v},", typeof.Field(i).Name, valueof.Field(i))
	}

	return formatStr
}

func (i *FlowPerfDataInfo) String() string {
	var reportStr string
	report := i.reportPerfStats
	if report != nil {
		reportStr = reflectFormat(*report)
	} else {
		reportStr = "nil"
	}

	return fmt.Sprintf("\nreportPerfStats:%v, \nperiodPerfStats:%v, \nflowPerfStats:%v",
		reportStr, i.periodPerfStats, i.flowPerfStats)
}

func (s *MetaPerfStats) String() string {
	return reflectFormat(*s)
}

// implement stats/GetCounter interface
func (p *MetaFlowPerf) GetCounter() interface{} {
	counter := &FlowPerfCounter{}
	counter, p.counter = p.counter, counter

	return counter
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

func (e FlowPerfError) returnError() error {
	if len(e.what) > 0 {
		return e
	}
	return nil
}

func (i *FlowInfo) String() string {
	return reflectFormat(*i)
}
