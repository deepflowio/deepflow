package flowgenerator

import (
	"container/list"
	"fmt"
	"reflect"
	"runtime"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
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

const (
	RTT_MAX = 10 * time.Second
)

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

type FlowPacketVariance struct {
	packetIntervalAvg      float64
	packetIntervalVariance float64
	packetSizeAvg          float64
	packetSizeVariance     float64
	lastPacketTimestamp    time.Duration
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
	packetVariance  FlowPacketVariance
}

type FlowPerfCounter struct {
	counter *FlowPerfStats
}

type FlowPerfStats struct {
	NewCpuPerf         int64  `statsd:"new_cpu"`              // new的平均性能
	UpdateCpuPerf      int64  `statsd:"update_cpu"`           // update的平均性能
	ReportCpuPerf      int64  `statsd:"report_cpu"`           // report的平均性能
	FlowCount          uint32 `statsd:"flow_count"`           // 每条流,计数加1
	ReportCount        int64  `statsd:"report_count"`         // 每次上报,计数加1
	PacketCount        int64  `statsd:"packet_count"`         // 每个包,计数加1
	InvalidPacketCount int64  `statsd:"invalid_packet_count"` // 每个异常包,计数加1
}

type FlowInfo struct {
	flowID            uint64
	ipSrc, ipDst      IP
	flowState         FlowState
	direction         bool
	totalPacketCount0 uint64
	totalPacketCount1 uint64
	arrTime0Last      time.Duration
	arrTime1Last      time.Duration
	tcpFlags0         uint8
	tcpFlags1         uint8
}

type MetaFlowPerf struct {
	ctrlInfo *FlowPerfCtrlInfo
	perfData *FlowPerfDataInfo
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

// 用于判断SeqSegment node是否与left或right连续
// 如果把SeqSegment看作是sequence number的集合，continuous可认为是node与left或right相交
func isContinuousSeqSegment(left, right, node *SeqSegment, flowInfo *FlowInfo) ContinuousFlag {
	flag := SEQ_NODE_DISCONTINUOUS

	if left != nil && left.seqNumber+left.length == node.seqNumber {
		left.length += node.length

		flag |= SEQ_NODE_LEFT_CONTINUOUS
	}

	if right != nil && node.seqNumber+node.length == right.seqNumber {
		right.seqNumber = node.seqNumber
		right.length += node.length

		flag |= SEQ_NODE_RIGHT_CONTINUOUS
	}

	return flag
}

// 当list超过最大限制长度时，合并SeqList中前两个节点
// 忽略调sequence最小的2个node之间的间隔,相当于认为包已收到
// 其带来的影响是，包被误认为是重传
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

// 如果把SeqSegment看作是sequence number的集合，retrans可认为是left包含node
func isRetransSeqSegment(left, node *SeqSegment) bool {
	if left == nil {
		return false
	}

	if node.seqNumber >= left.seqNumber && left.seqNumber+left.length >= node.seqNumber+node.length {
		return true
	}

	return false
}

// 如果把SeqSegment看作是sequence number的集合，error可认为是node与left或right相交
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

	l := p.seqList
	if l == nil {
		log.Warningf("flow info: %v, seqNumber list is nil, seqNumber data have lost", flowInfo)
		return SEQ_ERROR
	}
	if l.Len() == 0 {
		l.PushFront(node)
		return SEQ_NOT_CARE
	}

	// seqList为升序链表，此处，从后往前查找；直至找到seqNumber小于或等于node.seqNumber的节点
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
		log.Debugf("flow info: %v, node:%v out of range, left:%v, right:%v", flowInfo, node, left, right)
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
		log.Debugf("flow info: %v, seqList length exceed max length:%v, merge seqList first 2 element", flowInfo, SEQ_LIST_MAX_LEN)
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

	return tcpFlag == (TCP_ACK|TCP_PSH) && payloadLen > 1
}

// 需排除payload == 1的包
func isValidPayloadPacket(header *MetaPacket) bool {
	return header.PayloadLen > 1
}

// 对于payload == 0的keep-alive包，暂时没有好的处理办法，仅当作ACK包
// 暂且把ACK置位，payloadLen == 1的包认为是Tcp Keep-Alive
func isTcpKeepAlivePacket(header *MetaPacket) bool {
	tcpFlag := header.TcpData.Flags & TCP_FLAG_MASK
	payloadLen := header.PayloadLen

	return tcpFlag&TCP_ACK > 0 && payloadLen == 1
}

func adjustRtt(interval time.Duration) time.Duration {
	if interval > RTT_MAX {
		interval = 0
	}

	return interval
}

func calcTimeInterval(currentTime, lastTime time.Duration) time.Duration {
	return currentTime - lastTime
}

// 判断是否重传或错误
func (p *MetaFlowPerf) isInvalidRetransPacket(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flowInfo *FlowInfo, perfCounter *FlowPerfCounter) bool {
	isInvalid := false

	// 引入seqThreshold，用于连接建立阶段SYN,SYN/ACK, ACK包重传判断
	payloadLen := header.PayloadLen
	if isSynPacket(header) { // SYN包
		if sameDirection.seqThreshold == 0 {
			sameDirection.seqThreshold = header.TcpData.Seq + 1
		} else {
			if sameDirection.isSynReceived {
				p.perfData.calcRetransSyn(flowInfo.direction)
			}
		}
		sameDirection.isSynReceived = true

		return isInvalid
	}

	if isSynAckPacket(header) { // SYN/ACK包
		if sameDirection.seqThreshold == 0 {
			sameDirection.seqThreshold = header.TcpData.Seq + 1
			if oppositeDirection.seqThreshold == 0 {
				oppositeDirection.seqThreshold = header.TcpData.Ack
			}
		} else {
			p.perfData.calcRetransSyn(flowInfo.direction)
		}

		return isInvalid
	}

	if isAckPacket(header) {
		if header.TcpData.Seq == sameDirection.seqThreshold &&
			header.TcpData.Ack == oppositeDirection.seqThreshold {
			if sameDirection.isAckReceived == false {
				sameDirection.isAckReceived = true
			} else {
				p.perfData.calcRetransSyn(flowInfo.direction)
			}
		}

		return isInvalid
	}

	if !isValidPayloadPacket(header) {
		return isInvalid
	}

	// 连接建立后，即ESTABLISHED阶段，用SeqList判断包重传
	r := sameDirection.assertSeqNumber(header.TcpData, payloadLen, flowInfo)
	if r == SEQ_RETRANS {
		// established retrans
		p.perfData.calcRetrans(flowInfo.direction)
	} else if r == SEQ_ERROR {
		isInvalid = true
		perfCounter.counter.InvalidPacketCount += 1
	}

	return isInvalid
}

func isHandshakeAckpacket(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket) bool {
	return isAckPacket(header) && sameDirection.seqThreshold == header.TcpData.Seq && oppositeDirection.seqThreshold == header.TcpData.Ack
}

func (p *MetaFlowPerf) whenFlowOpening(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flowInfo *FlowInfo) bool {
	isOpeningPkt := false

	if sameDirection.getRttPrecondition() {
		// 不考虑SYN, SYN/ACK, PSH/ACK的情况
		if (flowInfo.direction == TCP_DIR_CLIENT && isHandshakeAckpacket(sameDirection, oppositeDirection, header)) ||
			(flowInfo.direction == TCP_DIR_SERVER && isSynAckPacket(header)) &&
				oppositeDirection.isReplyPacket(header) {
			if rttSyn := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); rttSyn > 0 {
				p.perfData.calcRttSyn(rttSyn, flowInfo.direction)
			}
			isOpeningPkt = true
		}
	}

	if isSynPacket(header) || isSynAckPacket(header) {
		if header.TcpData.WinScale > 0 {
			sameDirection.winScale = WIN_SCALE_FLAG | uint8(Min(int(WIN_SCALE_MAX), int(header.TcpData.WinScale)))
		}

		oppositeDirection.setRttPrecondition()
		sameDirection.resetRttPrecondition()
		sameDirection.resetArtPrecondition()
		oppositeDirection.resetArtPrecondition()

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
			if rtt := adjustRtt(calcTimeInterval(header.Timestamp, oppositeDirection.timestamp)); rtt > 0 {
				p.perfData.calcRtt(rtt, flowInfo.direction)
			}
		}
	}

	// art--用连续的PSH/ACK(payloadLen>0)和ACK(payloadLen==0)[可选]、PSH/ACK(payloadLen>0)计算art值，
	if sameDirection.getArtPrecondition() {
		if isValidPayloadPacket(header) && sameDirection.isNextPacket(header) {
			if art := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); art > 0 {
				p.perfData.calcArt(art, flowInfo.direction)
			}
		}
	}

	// 收到ACK包，仅能用于同向判断是否计算art
	if isAckPacket(header) {
		sameDirection.resetRttPrecondition()

		oppositeDirection.resetRttPrecondition()
		oppositeDirection.resetArtPrecondition()
	}

	// 收到PSH/ACK包，仅可用于反向判断是否计算rtt, art
	if isPshAckPacket(header) {
		sameDirection.resetArtPrecondition()
		sameDirection.resetRttPrecondition()

		oppositeDirection.setRttPrecondition()
		oppositeDirection.setArtPrecondition()
	}

	//zerowin, pshUrgCount0
	winSize := uint32(header.TcpData.WinSize)
	if sameDirection.winScale&oppositeDirection.winScale&WIN_SCALE_FLAG > 0 {
		winSize = winSize << (sameDirection.winScale & WIN_SCALE_MASK)
	}
	// winSize == 0 or zero window
	if winSize == 0 {
		p.perfData.calcZeroWin(flowInfo.direction)
	}

	// PSH/URG
	if header.TcpData.Flags&TCP_FLAG_MASK == (TCP_ACK | TCP_PSH | TCP_URG) {
		p.perfData.calcPshUrg(flowInfo.direction)
	}
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (p *MetaFlowPerf) update(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, flow *FlowInfo, perfCounter *FlowPerfCounter) {
	// 统计有效重传，识别并排除无效的假重传包
	if p.isInvalidRetransPacket(sameDirection, oppositeDirection, header, flow, perfCounter) {
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
}

// 计算rttSyn值
func (i *FlowPerfDataInfo) calcRttSyn(rtt time.Duration, direction bool) {
	if direction == TCP_DIR_CLIENT {
		i.flowPerfStats.rttSyn0 += rtt
		i.flowPerfStats.rtt0Count += 1
	} else {
		i.flowPerfStats.rttSyn1 += rtt
		i.flowPerfStats.rtt1Count += 1
	}
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
}

// check if tcpHeader is valid
func checkTcpFlags(tcpFlags uint8) bool {
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

func NewMetaFlowPerf(perfCounter *FlowPerfCounter) *MetaFlowPerf {
	current := time.Now()
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
	}

	perfCounter.counter.FlowCount++
	perfCounter.counter.NewCpuPerf = calcAvgTime(perfCounter.counter.NewCpuPerf,
		time.Since(current).Nanoseconds(), int64(perfCounter.counter.FlowCount))

	return meta
}

func (p *MetaFlowPerf) calcVarianceStats(header *MetaPacket, flowInfo *FlowInfo) {
	packetVariance := &p.perfData.packetVariance

	lastIntervalAvg := packetVariance.packetIntervalAvg
	lastSizeAvg := packetVariance.packetSizeAvg

	packetTimestampUs := header.Timestamp / time.Microsecond
	packetCount := int64(flowInfo.totalPacketCount0 + flowInfo.totalPacketCount1)
	packetInterval := float64(packetTimestampUs - packetVariance.lastPacketTimestamp)

	packetVariance.lastPacketTimestamp = packetTimestampUs

	if packetCount > 2 {
		packetVariance.packetIntervalAvg = lastIntervalAvg + (packetInterval-lastIntervalAvg)/float64(packetCount-1)
		packetVariance.packetIntervalVariance = ((packetInterval-lastIntervalAvg)*(packetInterval-packetVariance.packetIntervalAvg) +
			packetVariance.packetIntervalVariance) / float64(packetCount-2)

		packetVariance.packetSizeAvg = lastSizeAvg + (float64(header.PacketLen)-lastSizeAvg)/float64(packetCount)
		packetVariance.packetSizeVariance = (((float64(header.PacketLen) - lastSizeAvg) * (float64(header.PacketLen) - packetVariance.packetSizeAvg)) +
			packetVariance.packetSizeVariance) / float64(packetCount-1)
	} else if packetCount > 1 {
		packetVariance.packetSizeAvg = lastSizeAvg + (float64(header.PacketLen)-lastSizeAvg)/float64(packetCount)
		packetVariance.packetSizeVariance = (((float64(header.PacketLen) - lastSizeAvg) * (float64(header.PacketLen) - packetVariance.packetSizeAvg)) +
			packetVariance.packetSizeVariance) / float64(packetCount-1)

		packetVariance.packetIntervalAvg = float64(packetInterval)
		packetVariance.packetIntervalVariance = 0
	} else {
		packetVariance.packetSizeAvg = float64(header.PacketLen)
		packetVariance.packetSizeVariance = 0
	}
}

// 异常flag判断，方向识别，payloadLen计算等
// 去除功能不相关报文
func (p *MetaFlowPerf) preprocess(header *MetaPacket, flowInfo *FlowInfo, perfCounter *FlowPerfCounter) bool {
	if header.TcpData == nil { // invalid tcp header
		return false
	}

	if ok := checkTcpFlags(header.TcpData.Flags & TCP_FLAG_MASK); !ok {
		perfCounter.counter.InvalidPacketCount += 1

		log.Debugf("flow info:%v, invalid packet, err tcpFlag:0x%x", flowInfo, header.TcpData.Flags&TCP_FLAG_MASK)
		return false
	}

	return true
}

// update flow performace quantify state and data
func (p *MetaFlowPerf) Update(header *MetaPacket, reply bool, flowExtra *FlowExtra, perfCounter *FlowPerfCounter) error {
	var err FlowPerfError
	var sameDirection, oppositeDirection *TcpSessionPeer

	current := time.Now()

	if header == nil || flowExtra == nil {
		err = FlowPerfError{what: "packet header or flow info is nil"}
		return err
	}

	flowInfo := initFlowInfo(flowExtra.taggedFlow, flowExtra.flowState, reply, flowExtra.reversed)
	p.calcVarianceStats(header, flowInfo)

	if valid := p.preprocess(header, flowInfo, perfCounter); valid {
		if reply == TCP_DIR_CLIENT {
			sameDirection = &p.ctrlInfo.tcpSession[Bool2Int(TCP_DIR_CLIENT)]
			oppositeDirection = &p.ctrlInfo.tcpSession[Bool2Int(TCP_DIR_SERVER)]
		} else {
			sameDirection = &p.ctrlInfo.tcpSession[Bool2Int(TCP_DIR_SERVER)]
			oppositeDirection = &p.ctrlInfo.tcpSession[Bool2Int(TCP_DIR_CLIENT)]
		}

		if time.Duration(header.Timestamp) < sameDirection.timestamp || time.Duration(header.Timestamp) < oppositeDirection.timestamp {
			perfCounter.counter.InvalidPacketCount += 1
			log.Debugf("flow info: %v, packet timestamp error, same last:%v, opposite last:%v, packet:%v", flowInfo,
				sameDirection.timestamp, oppositeDirection.timestamp, header.Timestamp)
			err = FlowPerfError{what: "packet timestamp error"}
			return err
		}

		// 根据packetHeader, direction重建状态机
		//p.reestablishFsm(sameDirection, oppositeDirection, header, flow)
		p.update(sameDirection, oppositeDirection, header, flowInfo, perfCounter)

		// 更新包数据
		sameDirection.updateData(header)
	} else { // art, rtt控制字段置位
		p.ctrlInfo.tcpSession[0].resetRttPrecondition()
		p.ctrlInfo.tcpSession[0].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetRttPrecondition()
	}

	perfCounter.counter.PacketCount++
	perfCounter.counter.UpdateCpuPerf = calcAvgTime(perfCounter.counter.UpdateCpuPerf,
		time.Since(current).Nanoseconds(), perfCounter.counter.PacketCount)
	return nil
}

func Report(flowPerf *MetaFlowPerf, reverse bool, perfCounter *FlowPerfCounter) *TcpPerfStats {
	if flowPerf == nil {
		return nil
	}

	if flowPerf.perfData != nil {
		current := time.Now()
		report := &TcpPerfStats{}
		flowPerf.perfData.calcReportFlowPerfStats(reverse)

		if reverse == true {
			flowPerf.perfData.exchangeReportFlowPerfStats()
		}

		flowPerf.perfData.reportPerfStats, report = report, flowPerf.perfData.reportPerfStats

		flowPerf.perfData.resetPeriodPerfStats()

		perfCounter.counter.ReportCount++
		perfCounter.counter.ReportCpuPerf = calcAvgTime(perfCounter.counter.ReportCpuPerf,
			time.Since(current).Nanoseconds(), perfCounter.counter.ReportCount)
		return report
	}

	return nil
}

func checkIfDoFlowPerf(flowExtra *FlowExtra, counter *FlowPerfCounter) bool {
	if flowExtra.taggedFlow.PolicyData == nil {
		return false
	}
	if flowExtra.taggedFlow.PolicyData.ActionList&ACTION_PERFORMANCE > 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = NewMetaFlowPerf(counter)
		}
		return true
	}

	return false
}

func (i *FlowPerfDataInfo) exchangeReportFlowPerfStats() {
	report := i.reportPerfStats

	report.TcpPerfCountsPeerSrc, report.TcpPerfCountsPeerDst = TcpPerfCountsPeerSrc(report.TcpPerfCountsPeerDst), TcpPerfCountsPeerDst(report.TcpPerfCountsPeerSrc)
}

func (i *FlowPerfDataInfo) calcReportFlowPerfStats(reverse bool) {
	report := i.reportPerfStats
	period := i.periodPerfStats
	flow := i.flowPerfStats

	if !reverse {
		if period.art1Count > 0 {
			report.ART = period.art1Sum / time.Duration(period.art1Count)
		}

		if period.rtt1Count > 0 {
			report.RTT = period.rtt1Sum / time.Duration(period.rtt1Count)
		}
	} else {
		if period.art0Count > 0 {
			report.ART = period.art0Sum / time.Duration(period.art0Count)
		}

		if period.rtt0Count > 0 {
			report.RTT = period.rtt0Sum / time.Duration(period.rtt0Count)
		}
	}

	report.RTTSyn = flow.rttSyn0 + flow.rttSyn1

	report.TcpPerfCountsPeerSrc.SynRetransCount = period.retransSyn0
	report.TcpPerfCountsPeerDst.SynRetransCount = period.retransSyn1

	report.TcpPerfCountsPeerSrc.RetransCount = period.retrans0
	report.TcpPerfCountsPeerDst.RetransCount = period.retrans1
	report.TotalRetransCount = flow.retrans0 + flow.retrans1

	report.TcpPerfCountsPeerSrc.ZeroWinCount = period.zeroWinCount0
	report.TcpPerfCountsPeerDst.ZeroWinCount = period.zeroWinCount1
	report.TotalZeroWinCount = flow.zeroWinCount0 + flow.zeroWinCount1

	report.TcpPerfCountsPeerSrc.PshUrgCount = period.pshUrgCount0
	report.TcpPerfCountsPeerDst.PshUrgCount = period.pshUrgCount1
	report.TotalPshUrgCount = flow.pshUrgCount0 + flow.pshUrgCount1

	report.PacketIntervalAvg = uint64(i.packetVariance.packetIntervalAvg)
	report.PacketIntervalVariance = uint64(i.packetVariance.packetIntervalVariance)
	report.PacketSizeVariance = uint64(i.packetVariance.packetSizeVariance)
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
	if i == nil {
		return ""
	}

	return reflectFormat(*i)
}

func initFlowInfo(flow *TaggedFlow, state FlowState, reply, reversed bool) *FlowInfo {
	if reversed {
		return &FlowInfo{
			flowState:         state,
			direction:         reply,
			flowID:            flow.FlowID,
			totalPacketCount0: flow.FlowMetricsPeerDst.TotalPacketCount,
			totalPacketCount1: flow.FlowMetricsPeerSrc.TotalPacketCount,
			arrTime0Last:      flow.FlowMetricsPeerDst.ArrTimeLast,
			arrTime1Last:      flow.FlowMetricsPeerSrc.ArrTimeLast,
			tcpFlags0:         flow.FlowMetricsPeerDst.TCPFlags,
			tcpFlags1:         flow.FlowMetricsPeerSrc.TCPFlags,
		}
	} else {
		return &FlowInfo{
			flowState:         state,
			direction:         reply,
			flowID:            flow.FlowID,
			totalPacketCount0: flow.FlowMetricsPeerSrc.TotalPacketCount,
			totalPacketCount1: flow.FlowMetricsPeerDst.TotalPacketCount,
			arrTime0Last:      flow.FlowMetricsPeerSrc.ArrTimeLast,
			arrTime1Last:      flow.FlowMetricsPeerDst.ArrTimeLast,
			tcpFlags0:         flow.FlowMetricsPeerSrc.TCPFlags,
			tcpFlags1:         flow.FlowMetricsPeerDst.TCPFlags,
		}
	}
}

func NewFlowPerfCounter() FlowPerfCounter {
	return FlowPerfCounter{
		&FlowPerfStats{},
	}
}

func (c *FlowPerfCounter) String() string {
	return reflectFormat(*c)
}

func (c *FlowPerfCounter) Close() {
	stats.DeregisterCountable(c)
}

// implement stats/GetCounter interface
func (c *FlowPerfCounter) GetCounter() interface{} {
	counter := &FlowPerfStats{}
	c.counter, counter = counter, c.counter

	return counter
}

func calcAvgTime(average, consume, times int64) int64 {
	if times < 2 || average == 0 {
		return consume
	}

	return average + (consume-average)/times
}
