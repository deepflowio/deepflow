package flowgenerator

import (
	"fmt"
	"reflect"
	"runtime"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type ContinuousFlag uint8
type TcpConnSession = [2]TcpSessionPeer
type PacketSeqTypeInSeqList uint8

const (
	FP_NAME                  = "flow-perf"
	SEQ_NUMBER_LOW_THREHOLD  = uint32(0x40000000)
	SEQ_NUMBER_HIGH_THREHOLD = uint32(0xc0000000)
)

const (
	SEQ_NODE_DISCONTINUOUS ContinuousFlag = 0
	SEQ_NODE_LT_CONTINUOUS                = 1 << iota
	SEQ_NODE_GTE_CONTINUOUS
	SEQ_NODE_BOTH_CONTINUOUS = SEQ_NODE_LT_CONTINUOUS | SEQ_NODE_GTE_CONTINUOUS
)

const (
	SEQ_ERROR PacketSeqTypeInSeqList = iota
	SEQ_RETRANS
	SEQ_NOT_CARE
	SEQ_MERGE
	SEQ_DISCONTINUOUS
	SEQ_CONTINUOUS
	SEQ_CONTINUOUS_BOTH
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

const FLOW_PERF_ACTION_FLAGS = ACTION_TCP_FLOW_PERF_COUNTING | ACTION_FLOW_STORING | ACTION_GEO_POSITIONING

type SeqSegment struct { // 避免乱序，识别重传
	seqNumber uint32
	length    uint32
}

type TcpSessionPeer struct {
	seqArray  [SEQ_LIST_MAX_LEN]SeqSegment
	arraySize int

	timestamp time.Duration

	seqThreshold uint32 // fast SynRetrans Check
	seq          uint32
	payloadLen   uint32
	winSize      uint16
	winScale     uint8

	isAckReceived bool // AckRetrans check
	isSynReceived bool

	isAckPacket   bool
	canCalcRtt    bool
	canCalcRttSyn bool
	canCalcArt    bool
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
	rttSyn0Flag, rttSyn1Flag                   bool

	retrans0, retrans1       uint32
	retransSyn0, retransSyn1 uint32

	pshUrgCount0, pshUrgCount1   uint32
	zeroWinCount0, zeroWinCount1 uint32
}

type FlowPerfDataInfo struct {
	periodPerfStats MetaPerfStats
	flowPerfStats   MetaPerfStats
	packetVariance  FlowPacketVariance
}

type FlowPerfCounter struct {
	stats.Closable

	counter *FlowPerfStats
}

type FlowPerfStats struct {
	ReportCount        int64 `statsd:"report_count"`         // 每次上报,计数加1
	IgnorePacketCount  int64 `statsd:"ignore_packet_count"`  // 每个忽略包,计数加1
	InvalidPacketCount int64 `statsd:"invalid_packet_count"` // 每个异常包,计数加1
}

type MetaFlowPerf struct {
	ctrlInfo FlowPerfCtrlInfo
	perfData FlowPerfDataInfo
}

func (t PacketSeqTypeInSeqList) String() string {
	typeStr := ""
	switch t {
	case SEQ_ERROR:
		typeStr = "error sequence"
		break
	case SEQ_RETRANS:
		typeStr = "retrans sequence"
		break
	case SEQ_NOT_CARE:
		typeStr = "not care sequence"
		break
	case SEQ_MERGE:
		typeStr = "merge sequence"
		break
	case SEQ_DISCONTINUOUS:
		typeStr = "discontinuous sequence"
		break
	case SEQ_CONTINUOUS:
		typeStr = "continuous sequence"
		break
	case SEQ_CONTINUOUS_BOTH:
		typeStr = "both continuous sequence"
		break
	default:
		typeStr = "error type"
		break
	}
	return typeStr
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

func (p *TcpSessionPeer) setRttSynPrecondition() {
	p.canCalcRttSyn = true
}

func (p *TcpSessionPeer) resetRttSynPrecondition() {
	p.canCalcRttSyn = false
}

func (p *TcpSessionPeer) getRttSynPrecondition() bool {
	return p.canCalcRttSyn
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

// merger array[at] and array[at+1] into array[at]
// 忽略调sequence最小的2个node之间的间隔,相当于认为包已收到
// 其带来的影响是，包被误认为是重传
func (p *TcpSessionPeer) mergeSeqListNode(at int) {
	gte := &p.seqArray[at]
	lt := &p.seqArray[at+1]
	gte.length = gte.seqNumber - lt.seqNumber + gte.length
	gte.seqNumber = lt.seqNumber
	// 合并后，需要reset被合并的node
	lt.length = 0
	lt.seqNumber = 0

	// 仅当被合并node不是最后一个node时，需要将被合并node之后的node往前移一位
	if at < p.arraySize-2 {
		copy(p.seqArray[at+1:], p.seqArray[at+2:])
	}
	p.arraySize--
}

// insert node to array[at]
func (p *TcpSessionPeer) insertSeqListNode(node SeqSegment, at int) {
	// 当插入的位置非末尾时，需将插入位置到末尾的所有node往后移一位
	// 同时，不会存在，当p.arraySize==16时，执行insert操作的情况，
	// 因为，当p.arraySize>=16时，需立即执行merge操作，使得p.arraySize始终<=15
	if at < p.arraySize {
		copy(p.seqArray[at+1:], p.seqArray[at:])
	}
	p.seqArray[at] = node
	p.arraySize++
}

// 检查当前node与list中seq最大的node的距离
func (p *TcpSessionPeer) checkSeqSegment(node SeqSegment) bool {
	// 检查seqNumber是否循环, 忽略循环包
	if node.seqNumber+node.length < node.seqNumber {
		return false
	}

	if p.arraySize == 0 {
		p.insertSeqListNode(node, 0)
		return false
	}

	// list倒序排序，故最大的seq范围节点index为0
	lastIdx := 0
	// 前一个包在seq范围的高3/4, 当前包在seq范围的低1/4
	// 意味着seq已循环，需清空list
	if node.seqNumber < SEQ_NUMBER_LOW_THREHOLD &&
		p.seqArray[lastIdx].seqNumber+p.seqArray[lastIdx].length >
			SEQ_NUMBER_HIGH_THREHOLD {
		// 清空list
		p.arraySize = 0
		// 插入当前包
		p.insertSeqListNode(node, 0)
		return false
	}

	// 前一个包在seq范围的低1/4, 当前包在seq范围的高3/4
	// 意味着之前的包重传或乱序了，忽略这类包
	if node.seqNumber > SEQ_NUMBER_HIGH_THREHOLD &&
		p.seqArray[lastIdx].seqNumber+p.seqArray[lastIdx].length <
			SEQ_NUMBER_LOW_THREHOLD {
		// 忽略当前包
		return false
	}

	return true
}

// 因数组中每个node.seqNumber默认为0，故seqArray为降序数组；直至找到seqNumber大于或等于node.seqNumber的节点
// 返回值
func (p *TcpSessionPeer) Search(node SeqSegment) (lt, gte *SeqSegment, index int) {
	for index = 0; index < p.arraySize; index++ {
		if node.seqNumber > p.seqArray[index].seqNumber { // 查找node在list中的位置
			break
		}
	}
	if index == 0 {
		gte = nil
	} else {
		gte = &p.seqArray[index-1]
	}

	if index == p.arraySize {
		lt = nil
	} else {
		lt = &p.seqArray[index]
	}
	return
}

// 用于判断SeqSegment node是否与lt或gte连续
// 如果把SeqSegment看作是sequence number的集合，continuous可认为是node与lt或gte相
func isContinuousSeqSegment(lt, gte, node *SeqSegment) ContinuousFlag {
	flag := SEQ_NODE_DISCONTINUOUS

	if lt != nil && lt.seqNumber+lt.length == node.seqNumber {
		lt.length += node.length

		flag |= SEQ_NODE_LT_CONTINUOUS
	}

	if gte != nil && node.seqNumber+node.length == gte.seqNumber {
		gte.seqNumber = node.seqNumber
		gte.length += node.length

		flag |= SEQ_NODE_GTE_CONTINUOUS
	}

	return flag
}

func checkRetrans(base, node *SeqSegment) bool {
	if node.seqNumber >= base.seqNumber &&
		base.seqNumber+base.length >= node.seqNumber+node.length {
		return true
	}

	return false
}

func isRetransSeqSegment(lt, gte, node *SeqSegment) bool {
	if gte == nil {
		return checkRetrans(lt, node)
	}
	return checkRetrans(gte, node)
}

// 如果把SeqSegment看作是sequence number的集合，error可认为是node与lt或gte相交
func isErrorSeqSegment(lt, gte, node *SeqSegment) bool {
	if gte != nil &&
		((node.seqNumber < gte.seqNumber && node.seqNumber+node.length > gte.seqNumber) ||
			node.seqNumber+node.length > gte.seqNumber+gte.length) {
		return true
	}

	if lt != nil && lt.seqNumber+lt.length > node.seqNumber {
		return true
	}

	return false
}

// 根据seqNumber判断包重传,连续,不连续
// 合并连续seqNumber
// 不连续则添加新节点, 构建升序链表
func (p *TcpSessionPeer) assertSeqNumber(tcpHeader *MetaPacketTcpHeader, payloadLen uint16) PacketSeqTypeInSeqList {
	var flag PacketSeqTypeInSeqList
	var lt, gte *SeqSegment

	if payloadLen == 0 || tcpHeader.Seq == 0 {
		return SEQ_NOT_CARE
	}

	node := SeqSegment{seqNumber: tcpHeader.Seq, length: uint32(payloadLen)}
	if p.checkSeqSegment(node) == false {
		return SEQ_NOT_CARE
	}

	lt, gte, ltIndex := p.Search(node)
	if r := isRetransSeqSegment(lt, gte, &node); r {
		flag = SEQ_RETRANS
	} else if e := isErrorSeqSegment(lt, gte, &node); e {
		flag = SEQ_ERROR
	} else {
		if c := isContinuousSeqSegment(lt, gte, &node); c == SEQ_NODE_DISCONTINUOUS {
			p.insertSeqListNode(node, ltIndex)
			flag = SEQ_DISCONTINUOUS
			if p.arraySize >= SEQ_LIST_MAX_LEN {
				p.mergeSeqListNode(SEQ_LIST_MAX_LEN - 2)
				flag = SEQ_MERGE
			}
		} else if c == SEQ_NODE_BOTH_CONTINUOUS {
			p.mergeSeqListNode(ltIndex - 1)
			flag = SEQ_CONTINUOUS_BOTH
		} else {
			flag = SEQ_CONTINUOUS
		}
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

func (p *TcpSessionPeer) String() string {
	var list string

	data := fmt.Sprintf("timestamp:%v, seq:%v, payloadLen:%v, winSize:%v"+
		"winScale:%v, canCalcRtt:%v, canCalcArt:%v",
		p.timestamp, p.seq, p.payloadLen,
		p.winSize, p.winScale, p.canCalcRtt, p.canCalcArt)

	length := p.arraySize
	list = fmt.Sprintf("length:%v", length)
	if length > 0 {
		list = fmt.Sprintf("%s, %v", list, p.seqArray)
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
func (p *MetaFlowPerf) isInvalidRetransPacket(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, isFirstPacketDirection bool, perfCounter *FlowPerfCounter) bool {
	isInvalid := false

	// 引入seqThreshold，用于连接建立阶段SYN,SYN/ACK, ACK包重传判断
	payloadLen := header.PayloadLen
	if isSynPacket(header) { // SYN包
		if sameDirection.seqThreshold == 0 {
			sameDirection.seqThreshold = header.TcpData.Seq + 1
		} else {
			if sameDirection.isSynReceived {
				p.perfData.calcRetransSyn(isFirstPacketDirection)
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
			p.perfData.calcRetransSyn(isFirstPacketDirection)
		}

		return isInvalid
	}

	if isAckPacket(header) {
		if header.TcpData.Seq == sameDirection.seqThreshold &&
			header.TcpData.Ack == oppositeDirection.seqThreshold {
			if sameDirection.isAckReceived == false {
				sameDirection.isAckReceived = true
			} else {
				p.perfData.calcRetransSyn(isFirstPacketDirection)
			}
		}

		return isInvalid
	}

	if !isValidPayloadPacket(header) {
		return isInvalid
	}

	// 连接建立后，即ESTABLISHED阶段，用SeqList判断包重传
	r := sameDirection.assertSeqNumber(&(header.TcpData), payloadLen)
	if r == SEQ_RETRANS {
		// established retrans
		p.perfData.calcRetrans(isFirstPacketDirection)
	} else if r == SEQ_ERROR {
		isInvalid = true
		perfCounter.counter.InvalidPacketCount += 1
	}

	return isInvalid
}

func isFirstHandshakeAckpacket(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket) bool {
	return isAckPacket(header) && sameDirection.seq != header.TcpData.Seq && sameDirection.seqThreshold == header.TcpData.Seq && oppositeDirection.seqThreshold == header.TcpData.Ack
}

func (p *MetaFlowPerf) whenFlowOpening(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, isFirstPacketDirection bool) bool {
	isOpeningPkt := false

	if sameDirection.getRttSynPrecondition() {
		// 不考虑SYN, SYN/ACK, PSH/ACK的情况
		// rttsyn0 = Time(SYN/ACK) - Time(SYN)
		// rttSyn1 = Time(SYN/ACK/ACK) - Time(SYN/ACK)
		if (isFirstHandshakeAckpacket(sameDirection, oppositeDirection, header) || isSynAckPacket(header)) &&
			oppositeDirection.isReplyPacket(header) { // isReplyPacket检查当前包是否是反方向最近一个包的回包
			if rttSyn := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); rttSyn > 0 {
				p.perfData.calcRttSyn(rttSyn, isFirstPacketDirection)
			}
			isOpeningPkt = true
		}
	}

	if isSynPacket(header) || isSynAckPacket(header) {
		if header.TcpData.WinScale > 0 {
			sameDirection.winScale = WIN_SCALE_FLAG | uint8(Min(int(WIN_SCALE_MAX), int(header.TcpData.WinScale)))
		}

		sameDirection.resetRttSynPrecondition()
		oppositeDirection.setRttSynPrecondition()
		sameDirection.resetRttPrecondition()
		sameDirection.resetArtPrecondition()
		oppositeDirection.resetRttPrecondition()
		oppositeDirection.resetArtPrecondition()

		isOpeningPkt = true
	}

	return isOpeningPkt
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (p *MetaFlowPerf) whenFlowEstablished(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, isFirstPacketDirection bool) {
	// rtt--用连续的PSH/ACK(payloadLen>0)和反向ACK(payloadLen==0)计算rtt值
	if sameDirection.getRttPrecondition() {
		if isAckPacket(header) && oppositeDirection.isReplyPacket(header) {
			if rtt := adjustRtt(calcTimeInterval(header.Timestamp, oppositeDirection.timestamp)); rtt > 0 {
				p.perfData.calcRtt(rtt, isFirstPacketDirection)
			}
		}
	}

	// art--用连续的PSH/ACK(payloadLen>0)和ACK(payloadLen==0)[可选]、PSH/ACK(payloadLen>0)计算art值，
	if sameDirection.getArtPrecondition() {
		if isValidPayloadPacket(header) && sameDirection.isNextPacket(header) {
			if art := calcTimeInterval(header.Timestamp, oppositeDirection.timestamp); art > 0 {
				p.perfData.calcArt(art, isFirstPacketDirection)
			}
		}
	}

	if isAckPacket(header) {
		// 收到ACK包，仅能用于同向判断是否计算art
		sameDirection.resetRttPrecondition()

		oppositeDirection.resetRttPrecondition()
		oppositeDirection.resetArtPrecondition()
	} else if isPshAckPacket(header) {
		// 收到PSH/ACK包，仅可用于反向判断是否计算rtt, art
		sameDirection.resetArtPrecondition()
		sameDirection.resetRttPrecondition()

		oppositeDirection.setRttPrecondition()
		oppositeDirection.setArtPrecondition()
	} else {
		// 其它包，均为无效包，reset所有前置条件
		sameDirection.resetArtPrecondition()
		sameDirection.resetRttPrecondition()

		oppositeDirection.resetRttPrecondition()
		oppositeDirection.resetArtPrecondition()
	}

	//zerowin, pshUrgCount0
	winSize := uint32(header.TcpData.WinSize)
	if sameDirection.winScale&oppositeDirection.winScale&WIN_SCALE_FLAG > 0 {
		winSize = winSize << (sameDirection.winScale & WIN_SCALE_MASK)
	}
	// winSize == 0 or zero window
	if winSize == 0 {
		p.perfData.calcZeroWin(isFirstPacketDirection)
	}

	// PSH/URG
	if header.TcpData.Flags&TCP_FLAG_MASK == (TCP_ACK | TCP_PSH | TCP_URG) {
		p.perfData.calcPshUrg(isFirstPacketDirection)
	}
}

// 根据flag, direction, payloadLen或PSH,seq,ack重建状态机
// assume：包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
func (p *MetaFlowPerf) update(sameDirection, oppositeDirection *TcpSessionPeer, header *MetaPacket, isFirstPacketDirection bool, perfCounter *FlowPerfCounter) {
	// 统计有效重传，识别并排除无效的假重传包
	if p.isInvalidRetransPacket(sameDirection, oppositeDirection, header, isFirstPacketDirection, perfCounter) {
		p.ctrlInfo.tcpSession[0].resetRttPrecondition()
		p.ctrlInfo.tcpSession[0].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetArtPrecondition()
		p.ctrlInfo.tcpSession[1].resetRttPrecondition()
		return
	}

	// 计算RTT, ART
	if !p.whenFlowOpening(sameDirection, oppositeDirection, header, isFirstPacketDirection) {
		p.whenFlowEstablished(sameDirection, oppositeDirection, header, isFirstPacketDirection)
	}
}

// FIXME: art,rrt均值计算方法，需要增加影响因子
// 计算art值
func (i *FlowPerfDataInfo) calcArt(art time.Duration, isFirstPacketDirection bool) {
	if isFirstPacketDirection {
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
func (i *FlowPerfDataInfo) calcRtt(rtt time.Duration, isFirstPacketDirection bool) {
	if isFirstPacketDirection {
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
func (i *FlowPerfDataInfo) calcRttSyn(rtt time.Duration, isFirstPacketDirection bool) {
	if isFirstPacketDirection {
		i.flowPerfStats.rttSyn0 = rtt
		i.flowPerfStats.rttSyn0Flag = true
	} else {
		i.flowPerfStats.rttSyn1 = rtt
		i.flowPerfStats.rttSyn1Flag = true
	}
}

// 计算连接建立syn retrans值
func (i *FlowPerfDataInfo) calcRetransSyn(isFirstPacketDirection bool) {
	if isFirstPacketDirection {
		i.periodPerfStats.retransSyn0 += 1
		i.flowPerfStats.retransSyn0 += 1
	} else {
		i.periodPerfStats.retransSyn1 += 1
		i.flowPerfStats.retransSyn1 += 1
	}

	i.calcRetrans(isFirstPacketDirection)
}

// 计算retrans值
func (i *FlowPerfDataInfo) calcRetrans(isFirstPacketDirection bool) {
	if isFirstPacketDirection {
		i.periodPerfStats.retrans0 += 1
		i.flowPerfStats.retrans0 += 1
	} else {
		i.periodPerfStats.retrans1 += 1
		i.flowPerfStats.retrans1 += 1
	}
}

// 计算zero window包数量
func (i *FlowPerfDataInfo) calcZeroWin(isFirstPacketDirection bool) {
	if isFirstPacketDirection {
		i.periodPerfStats.zeroWinCount0 += 1
		i.flowPerfStats.zeroWinCount0 += 1
	} else {
		i.periodPerfStats.zeroWinCount1 += 1
		i.flowPerfStats.zeroWinCount1 += 1
	}
}

// 计算PSH/URG包数量
func (i *FlowPerfDataInfo) calcPshUrg(isFirstPacketDirection bool) {
	if isFirstPacketDirection {
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

func (p *MetaFlowPerf) calcVarianceStats(header *MetaPacket, packetCount int64) {
	packetVariance := &p.perfData.packetVariance

	lastIntervalAvg := packetVariance.packetIntervalAvg
	lastSizeAvg := packetVariance.packetSizeAvg

	packetTimestampUs := header.Timestamp / time.Microsecond
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
func (p *MetaFlowPerf) preprocess(header *MetaPacket, perfCounter *FlowPerfCounter) bool {
	if header.TcpData.DataOffset == 0 { // invalid tcp header or ip fragment
		return false
	}

	if ok := checkTcpFlags(header.TcpData.Flags & TCP_FLAG_MASK); !ok {
		perfCounter.counter.IgnorePacketCount += 1
		return false
	}

	return true
}

// update flow performace quantify state and data
func (p *MetaFlowPerf) Update(header *MetaPacket, isFirstPacketDirection bool, flowExtra *FlowExtra, perfCounter *FlowPerfCounter) error {
	var err FlowPerfError
	var sameDirection, oppositeDirection *TcpSessionPeer

	if header == nil || flowExtra == nil {
		err = FlowPerfError{what: "packet header or flow info is nil"}
		return err
	}

	// XXX: 统计数据未使用，暂时屏蔽
	// totalPacketCount := int64(flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].TotalPacketCount +
	// 	flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].TotalPacketCount)
	// p.calcVarianceStats(header, totalPacketCount)

	if valid := p.preprocess(header, perfCounter); valid {
		if isFirstPacketDirection {
			sameDirection = &p.ctrlInfo.tcpSession[0]
			oppositeDirection = &p.ctrlInfo.tcpSession[1]
		} else {
			sameDirection = &p.ctrlInfo.tcpSession[1]
			oppositeDirection = &p.ctrlInfo.tcpSession[0]
		}

		if time.Duration(header.Timestamp) < sameDirection.timestamp || time.Duration(header.Timestamp) < oppositeDirection.timestamp {
			perfCounter.counter.InvalidPacketCount += 1
			log.Debugf("flow info: %v, packet timestamp error, same last:%v, opposite last:%v, packet:%v", flowExtra,
				sameDirection.timestamp, oppositeDirection.timestamp, header.Timestamp)
			err = FlowPerfError{what: "packet timestamp error"}
			return err
		}

		// 根据packetHeader, direction重建状态机
		//p.reestablishFsm(sameDirection, oppositeDirection, header, flow)
		p.update(sameDirection, oppositeDirection, header, isFirstPacketDirection, perfCounter)

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

func resetPerfData(flowPerf *MetaFlowPerf) {
	if flowPerf != nil {
		flowPerf.perfData.resetPeriodPerfStats()
	}
}

func copyAndResetPerfData(flowPerf *MetaFlowPerf, flowReversed bool, perfCounter *FlowPerfCounter) *TcpPerfStats {
	if flowPerf == nil {
		return nil
	}

	report := AcquireTcpPerfStats()
	flowPerf.perfData.calcReportFlowPerfStats(report, flowReversed)
	flowPerf.perfData.resetPeriodPerfStats()

	perfCounter.counter.ReportCount++

	return report
}

func (i *FlowPerfDataInfo) calcReportFlowPerfStats(report *TcpPerfStats, flowReversed bool) {
	period := &i.periodPerfStats
	flow := &i.flowPerfStats

	if (flow.rttSyn0Flag || flow.rttSyn1Flag) && flow.rttSyn0 > 0 && flow.rttSyn1 > 0 {
		report.RTTSyn = flow.rttSyn0 + flow.rttSyn1
	}
	if flow.rttSyn0Flag {
		report.RTTSynClient = flow.rttSyn0
		flow.rttSyn0Flag = false
	}
	if flow.rttSyn1Flag {
		report.RTTSynServer = flow.rttSyn1
		flow.rttSyn1Flag = false
	}

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

	// XXX: 统计数据未使用，暂时屏蔽
	// report.PacketIntervalAvg = uint64(i.packetVariance.packetIntervalAvg)
	// report.PacketIntervalVariance = uint64(i.packetVariance.packetIntervalVariance)
	// report.PacketSizeVariance = uint64(i.packetVariance.packetSizeVariance)

	if !flowReversed {
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

		report.RTTSynClient, report.RTTSynServer = report.RTTSynServer, report.RTTSynClient
		report.TcpPerfCountsPeerSrc, report.TcpPerfCountsPeerDst = TcpPerfCountsPeerSrc(report.TcpPerfCountsPeerDst), TcpPerfCountsPeerDst(report.TcpPerfCountsPeerSrc)
	}
}

func (i *FlowPerfDataInfo) resetPeriodPerfStats() {
	i.periodPerfStats = MetaPerfStats{}
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

func (p *MetaFlowPerf) String() string {
	return fmt.Sprintf("flow ctrlInfo:%v,%v, \nflow perfData:%v",
		p.ctrlInfo.tcpSession[0], p.ctrlInfo.tcpSession[1], p.perfData)
}

func (i FlowPerfDataInfo) String() string {
	return fmt.Sprintf("periodPerfStats:%v\nflowPerfStats:%v\npacketVariance:%#v\n",
		i.periodPerfStats, i.flowPerfStats, i.packetVariance)
}

func (s MetaPerfStats) String() string {
	return reflectFormat(s)
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

func NewFlowPerfCounter() FlowPerfCounter {
	return FlowPerfCounter{
		counter: &FlowPerfStats{},
	}
}

func (c *FlowPerfCounter) String() string {
	return reflectFormat(*c)
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

func (p *MetaFlowPerf) resetMetaFlowPerf() {
	*p = MetaFlowPerf{}
}
