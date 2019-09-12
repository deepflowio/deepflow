package flowgenerator

import (
	"strconv"
	"sync"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"github.com/google/gopacket/layers"
)

var ( // 方便UT快速执行，定义为变量
	_TIME_SLOT_UNIT       = time.Second
	_PACKET_STAT_INTERVAL = time.Second
	_FLOW_STAT_INTERVAL   = time.Minute
)

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

type flowMapNode struct {
	flowExtra FlowExtra

	timeInUnit int64  // 记录 node 对应的绝对时间槽
	hash       uint64 // 哈希key，用于哈希桶定位和快速比较

	hashListNext int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev int32 // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在
	timeListNext int32 // 时间链表，含义与冲突链类似
	timeListPrev int32 // 时间链表，含义与冲突链类似
}

var blankFlowMapNodeForInit flowMapNode

type flowMapNodeBlock []flowMapNode

var flowMapNodeBlockPool = sync.Pool{New: func() interface{} {
	return flowMapNodeBlock(make([]flowMapNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type FlowMap struct {
	FlowGeo
	ringBuffer       []flowMapNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32              // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32              // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots      int // 上取整至2^N，哈希桶个数
	timeWindowSize int // 上取整至2^N，环形时间桶的槽位个数

	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]
	timeSlotHead []int32 // 时间桶，含义与 hashSlotHead 类似

	timeStart   time.Duration // 时间桶中的最早时间
	packetDelay time.Duration // Packet到底的最大Delay

	packetStatOutputBuffer []interface{} // 包统计信息输出的缓冲区
	flowStatOutputBuffer   []interface{} // 流统计信息输出的缓冲区
	packetAppQueue         queue.QueueWriter
	flowAppQueue           queue.QueueWriter
	lastFlush              time.Duration
	flowAppQueueFlush      time.Duration
	flushInterval          time.Duration

	stateMachineMaster []map[uint8]*StateValue
	stateMachineSlave  []map[uint8]*StateValue
	tcpServiceTable    *ServiceTable
	udpServiceTable    *ServiceTable

	capacity  int    // 最大容纳的Flow个数
	size      int    // 当前容纳的Flow个数
	width     int    // 当前哈希桶中的最长冲突链长度
	totalFlow uint64 // 用于生成当前分析器上全局唯一的FlowID
	id        int    // 在性能监控数据中标识不同的FlowMap

	counter     *FlowMapCounter
	perfCounter FlowPerfCounter
}

type FlowMapCounter struct {
	Total     uint64 `statsd:"total,counter"`
	Size      uint32 `statsd:"size,gauge"`
	MaxBucket uint32 `statsd:"max_bucket,gauge"`

	DropByCapacity   uint64 `statsd:"drop_by_capacity,counter"`
	DropBeforeWindow uint64 `statsd:"drop_before_window,counter"`
	DropAfterWindow  uint64 `statsd:"drop_after_window,counter"`
}

func (m *FlowMap) GetCounter() interface{} {
	counter := &FlowMapCounter{}
	m.counter, counter = counter, m.counter

	counter.Total = m.totalFlow
	counter.Size = uint32(m.size)
	counter.MaxBucket = uint32(m.width)
	m.width = 0

	return counter
}

func (m *FlowMap) Closed() bool {
	return false // never close
}

func (m *FlowMap) incIndex(index int32) int32 {
	index++
	if index>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		return 0
	}
	return index
}

func (m *FlowMap) decIndex(index int32) int32 {
	if index <= 0 {
		return int32(len(m.ringBuffer)<<_BLOCK_SIZE_BITS) - 1
	}
	return index - 1
}

func (m *FlowMap) getNode(index int32) *flowMapNode {
	return &m.ringBuffer[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (m *FlowMap) pushNodeToHashList(node *flowMapNode, nodeIndex int32, hash uint64) {
	hashSlot := int32(hash & uint64(m.hashSlots-1))
	node.hash = hash
	node.hashListNext = m.hashSlotHead[hashSlot]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hashSlot] = nodeIndex
}

func (m *FlowMap) pushNodeToTimeList(node *flowMapNode, nodeIndex int32, timeInUnit int64) {
	timeSlot := timeInUnit & int64(m.timeWindowSize-1)
	node.timeInUnit = timeInUnit
	node.timeListNext = m.timeSlotHead[timeSlot]
	node.timeListPrev = -1
	if node.timeListNext != -1 {
		m.getNode(node.timeListNext).timeListPrev = nodeIndex
	}
	m.timeSlotHead[timeSlot] = nodeIndex
}

func (m *FlowMap) removeNodeFromHashList(node *flowMapNode, newNext, newPrev int32) {
	if node.hashListPrev != -1 {
		prevNode := m.getNode(node.hashListPrev)
		prevNode.hashListNext = newNext
	} else {
		m.hashSlotHead[node.hash&uint64(m.hashSlots-1)] = newNext
	}

	if node.hashListNext != -1 {
		nextNode := m.getNode(node.hashListNext)
		nextNode.hashListPrev = newPrev
	}
}

func (m *FlowMap) removeNodeFromTimeList(node *flowMapNode, newNext, newPrev int32) {
	if node.timeListPrev != -1 {
		prevNode := m.getNode(node.timeListPrev)
		prevNode.timeListNext = newNext
	} else {
		m.timeSlotHead[node.timeInUnit&int64(m.timeWindowSize-1)] = newNext
	}

	if node.timeListNext != -1 {
		nextNode := m.getNode(node.timeListNext)
		nextNode.timeListPrev = newPrev
	}
}

func (m *FlowMap) removeNode(node *flowMapNode, nodeIndex int32) {
	// 从哈希链表、时间链表中删除
	m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
	m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)

	// 将节点交换至buffer头部
	if nodeIndex != m.bufferStartIndex {
		firstNode := m.getNode(m.bufferStartIndex)
		// 将firstNode内容拷贝至node
		*node = *firstNode
		// 修改firstNode在哈希链、时间链的上下游指向node
		m.removeNodeFromHashList(firstNode, nodeIndex, nodeIndex)
		m.removeNodeFromTimeList(firstNode, nodeIndex, nodeIndex)
		// 将firstNode初始化
		*firstNode = blankFlowMapNodeForInit
	} else {
		*node = blankFlowMapNodeForInit
	}

	// 释放头部节点
	if m.bufferStartIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		flowMapNodeBlockPool.Put(m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS])
		m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS] = nil
	}
	m.bufferStartIndex = m.incIndex(m.bufferStartIndex)

	m.size--
}

func (m *FlowMap) changeTimeSlot(node *flowMapNode, nodeIndex int32, timestamp time.Duration) {
	if node.timeInUnit != int64(timestamp/_TIME_SLOT_UNIT) {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入新的时间链表
		m.pushNodeToTimeList(node, nodeIndex, int64(timestamp/_TIME_SLOT_UNIT))
	}
}

func (m *FlowMap) flushQueue(now time.Duration) {
	if now-m.lastFlush > m.flushInterval {
		if len(m.packetStatOutputBuffer) > 0 {
			m.packetAppQueue.Put(m.packetStatOutputBuffer...)
			m.packetStatOutputBuffer = m.packetStatOutputBuffer[:0]
		}
		if len(m.flowStatOutputBuffer) > 0 {
			m.flowAppQueue.Put(m.flowStatOutputBuffer...)
			m.flowStatOutputBuffer = m.flowStatOutputBuffer[:0]
		}
		m.lastFlush = now
	}
}

func (m *FlowMap) pushToPacketStatsQueue(taggedFlow *datatype.TaggedFlow) {
	m.packetStatOutputBuffer = append(m.packetStatOutputBuffer, taggedFlow)
	if len(m.packetStatOutputBuffer) >= QUEUE_BATCH_SIZE {
		m.packetAppQueue.Put(m.packetStatOutputBuffer...)
		m.packetStatOutputBuffer = m.packetStatOutputBuffer[:0]
	}
}

func (m *FlowMap) pushToFlowStatsQueue(taggedFlow *datatype.TaggedFlow) {
	m.flowStatOutputBuffer = append(m.flowStatOutputBuffer, taggedFlow)
	if len(m.flowStatOutputBuffer) >= QUEUE_BATCH_SIZE {
		m.flowAppQueue.Put(m.flowStatOutputBuffer...)
		m.flowStatOutputBuffer = m.flowStatOutputBuffer[:0]
	}
}

func (m *FlowMap) removeAndOutput(node *flowMapNode, nodeIndex int32, timestamp time.Duration) {
	flowExtra := &node.flowExtra
	taggedFlow := flowExtra.taggedFlow

	// 输出统计数据
	if taggedFlow.PolicyData.ActionFlags&FLOW_ACTION != 0 {
		taggedFlow.AddReferenceCount()

		flowExtra.setEndTimeAndDuration(timestamp)
		calcCloseType(taggedFlow, flowExtra.flowState)
		taggedFlow.TcpPerfStats = copyAndResetPerfData(flowExtra.metaFlowPerf, flowExtra.reversed, &m.perfCounter)
		m.pushToFlowStatsQueue(taggedFlow)
	}
	if taggedFlow.PolicyData.ActionFlags&PACKET_ACTION != 0 && flowExtra.packetInTick {
		taggedFlow.AddReferenceCount()

		m.pushToPacketStatsQueue(taggedFlow)
	}

	// 释放FlowExtra指针占用的内存
	datatype.ReleaseTaggedFlow(taggedFlow)
	ReleaseMetaFlowPerf(flowExtra.metaFlowPerf)

	// 删除buffer节点
	m.removeNode(node, nodeIndex)
}

func (m *FlowMap) copyAndOutput(node *flowMapNode, timestamp time.Duration) {
	flowExtra := &node.flowExtra
	taggedFlow := flowExtra.taggedFlow

	// 如果timestamp和上一个包不在一个_PACKET_STAT_INTERVAL，输出Packet统计信息并清零
	if flowExtra.packetInTick && timestamp/_PACKET_STAT_INTERVAL != taggedFlow.PacketStatTime/_PACKET_STAT_INTERVAL {
		if taggedFlow.PolicyData.ActionFlags&PACKET_ACTION != 0 {
			outputTaggedFlow := datatype.CloneTaggedFlowForPacketStat(taggedFlow)
			m.pushToPacketStatsQueue(outputTaggedFlow)
		}
		flowExtra.resetPacketStatInfo() // 清零包统计数据
	}

	// 如果timestamp和上一个包不在一个_FLOW_STAT_INTERVAL，输出Flow统计信息并清零
	// 注意：流统计需要考虑包到达时间的延时容差，即若timestamp落在更靠前的统计周期内时，数据仍然计入当前统计周期
	if timestamp/_FLOW_STAT_INTERVAL > taggedFlow.StartTime/_FLOW_STAT_INTERVAL {
		flowExtra.setEndTimeAndDuration(timestamp / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL)
		if taggedFlow.PolicyData.ActionFlags&FLOW_ACTION != 0 {
			outputTaggedFlow := datatype.CloneTaggedFlow(taggedFlow)
			outputTaggedFlow.CloseType = datatype.CloseTypeForcedReport
			outputTaggedFlow.TcpPerfStats = copyAndResetPerfData(flowExtra.metaFlowPerf, flowExtra.reversed, &m.perfCounter)
			m.pushToFlowStatsQueue(outputTaggedFlow)
		} else {
			resetPerfData(flowExtra.metaFlowPerf)
		}
		flowExtra.resetFlowStatInfo(timestamp / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL) // 清零流统计数据
	}
}

func (m *FlowMap) isTimeInWindow(timestamp time.Duration) bool {
	if m.timeStart == 0 {
		m.timeStart = timestamp/_TIME_SLOT_UNIT*_TIME_SLOT_UNIT - m.packetDelay
		return true
	}

	if timestamp < m.timeStart {
		m.counter.DropBeforeWindow++
		return false
	} else if timestamp+_TIME_SLOT_UNIT >= m.timeStart+time.Duration(m.timeWindowSize)*_TIME_SLOT_UNIT {
		m.counter.DropAfterWindow++
		return false
	}
	return true
}

// 外部直接调用InjectFlushTicker时，timestamp需设置为now。返回值为false表示传入时间没有落在窗口中。
func (m *FlowMap) InjectFlushTicker(timestamp time.Duration) bool {
	if !m.isTimeInWindow(timestamp) {
		return false
	}
	timestamp -= m.packetDelay // 根据包到达时间的容差调整
	if timestamp < m.timeStart {
		return true
	}

	next := int32(0)
	startTimeInUnit := int64(m.timeStart / _TIME_SLOT_UNIT)
	endTimeInUnit := int64(timestamp / _TIME_SLOT_UNIT)
	for timeInUnit := startTimeInUnit; timeInUnit < endTimeInUnit; timeInUnit++ { // 扫描过期的时间槽
		timeHead := m.timeSlotHead[timeInUnit&int64(m.timeWindowSize-1)]
		for timeListNext := timeHead; timeListNext != -1; timeListNext = next { // 扫描特定时间点的链表
			node := m.getNode(timeListNext)
			next = node.timeListNext // node可能发生删除或移动，缓存next

			// 若Flow已经超时，直接输出
			timeout := node.flowExtra.recentTime + node.flowExtra.timeout
			if timestamp >= timeout {
				m.removeAndOutput(node, timeListNext, timeout)
				// 若next正好指向删掉节点之前的buffer头部，需要将next矫正至node本身
				// 因为删除机制会将被删除的节点交换至buffer头部进行删除
				if next == m.decIndex(m.bufferStartIndex) {
					next = timeListNext
				}
				continue
			}

			// 输出未超时Flow的统计信息
			m.copyAndOutput(node, timestamp)

			// 由于包、流统计信息已清零，将节点移动至下一个流统计的时间，或者最终超时的时间
			nextFlowStatOutputTime := timestamp/_FLOW_STAT_INTERVAL*_FLOW_STAT_INTERVAL + _FLOW_STAT_INTERVAL
			if nextFlowStatOutputTime > timeout {
				nextFlowStatOutputTime = timeout
			}
			m.changeTimeSlot(node, timeListNext, nextFlowStatOutputTime)
		}
	}

	m.timeStart = timestamp / _TIME_SLOT_UNIT * _TIME_SLOT_UNIT
	m.flushQueue(timestamp)
	return true
}

func (m *FlowMap) updateNode(node *flowMapNode, nodeIndex int32, meta *datatype.MetaPacket) {
	flowExtra := &node.flowExtra

	// 1. 输出上一个统计周期的统计信息
	m.copyAndOutput(node, meta.Timestamp)

	// 2. 更新Flow状态，判断是否已结束
	if meta.Protocol == layers.IPProtocolTCP {
		flowClosed := m.updateTcpFlow(flowExtra, meta)
		if m.checkIfDoFlowPerf(flowExtra) {
			serverToClient := (meta.Direction == datatype.SERVER_TO_CLIENT)
			flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed == serverToClient, flowExtra, &m.perfCounter)
		}
		if flowClosed {
			m.removeAndOutput(node, nodeIndex, meta.Timestamp)
			return
		}
	} else if meta.Protocol == layers.IPProtocolUDP {
		m.updateUdpFlow(flowExtra, meta)
	} else if meta.EthType != layers.EthernetTypeIPv4 {
		m.updateEthOthersFlow(flowExtra, meta)
	} else {
		m.updateIpOthersFlow(flowExtra, meta)
	}

	// 3. 由于包、流统计信息已清零，将节点移动至包对应的时间槽
	m.changeTimeSlot(node, nodeIndex, meta.Timestamp)
}

func (m *FlowMap) newNode(meta *datatype.MetaPacket, hash uint64) {
	// buffer空间检查
	if m.size >= m.capacity {
		m.counter.DropByCapacity++
		return
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = flowMapNodeBlockPool.Get().(flowMapNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++
	m.totalFlow++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, m.bufferEndIndex, hash)
	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex, int64(meta.Timestamp/_TIME_SLOT_UNIT))

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)

	// 初始化Flow
	flowExtra := &node.flowExtra
	if meta.Protocol == layers.IPProtocolTCP {
		m.initTcpFlow(flowExtra, meta)
		if m.checkIfDoFlowPerf(flowExtra) {
			serverToClient := (meta.Direction == datatype.SERVER_TO_CLIENT)
			flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed == serverToClient, flowExtra, &m.perfCounter)
		}
	} else if meta.Protocol == layers.IPProtocolUDP {
		m.initUdpFlow(flowExtra, meta)
	} else if meta.EthType != layers.EthernetTypeIPv4 {
		m.initEthOthersFlow(flowExtra, meta)
	} else {
		m.initIpOthersFlow(flowExtra, meta)
	}
}

func (m *FlowMap) InjectMetaPacket(hash uint64, meta *datatype.MetaPacket) {
	// 滑动时间窗口
	if !m.InjectFlushTicker(meta.Timestamp) {
		// 包的时间不在时间窗口中，忽略
		return
	}

	// 查找对应Flow所在的节点
	width := 0
	next := int32(0)
	hashHead := m.hashSlotHead[hash&uint64(m.hashSlots-1)]
	for hashListNext := hashHead; hashListNext != -1; hashListNext = next {
		node := m.getNode(hashListNext)
		next = node.hashListNext // node可能发生删除或移动，缓存next
		width++

		if node.hash == hash && node.flowExtra.Match(meta) {
			m.updateNode(node, hashListNext, meta)
			next = -1 // 由于会发生节点删除，此时next不再有效
			return
		}
	}
	if m.width < width+1 {
		m.width = width + 1
	}

	// 未找到Flow，需要插入新的节点
	m.newNode(meta, hash)
}

func minPowerOfTwo(v int) int {
	for i := uint32(0); i < 30; i++ {
		if v <= 1<<i {
			return 1 << i
		}
	}
	return 1
}

func NewFlowMap(hashSlots, capacity, id int, timeWindow, packetDelay, flushInterval time.Duration, packetAppQueue, flowAppQueue queue.QueueWriter) *FlowMap {
	hashSlots = minPowerOfTwo(hashSlots)
	if timeWindow < _FLOW_STAT_INTERVAL {
		timeWindow = _FLOW_STAT_INTERVAL
	}
	timeWindowSize := minPowerOfTwo(int((timeWindow + packetDelay + _TIME_SLOT_UNIT) / _TIME_SLOT_UNIT))

	m := &FlowMap{
		FlowGeo:                innerFlowGeo,
		ringBuffer:             make([]flowMapNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE*_BLOCK_SIZE+1),
		hashSlots:              hashSlots,
		timeWindowSize:         timeWindowSize,
		hashSlotHead:           make([]int32, hashSlots),
		timeSlotHead:           make([]int32, timeWindowSize),
		packetDelay:            packetDelay,
		packetStatOutputBuffer: make([]interface{}, 0, 256),
		flowStatOutputBuffer:   make([]interface{}, 0, 256),
		packetAppQueue:         packetAppQueue,
		flowAppQueue:           flowAppQueue,
		flushInterval:          flushInterval,
		stateMachineMaster:     make([]map[uint8]*StateValue, FLOW_STATE_MAX), // FIXME: 优化为[][]
		stateMachineSlave:      make([]map[uint8]*StateValue, FLOW_STATE_MAX), // FIXME: 优化为[][]
		tcpServiceTable:        NewServiceTable(capacity),
		udpServiceTable:        NewServiceTable(capacity),
		id:                     id,
		capacity:               capacity,
		counter:                &FlowMapCounter{},
		perfCounter:            NewFlowPerfCounter(),
	}
	m.initStateMachineMaster()
	m.initStateMachineSlave()
	tags := stats.OptionStatTags{"id": strconv.Itoa(id)}
	stats.RegisterCountable("flow-map", m, tags)
	stats.RegisterCountable(FP_NAME, &m.perfCounter, tags)

	for i := 0; i < len(m.hashSlotHead); i++ {
		m.hashSlotHead[i] = -1
	}
	for i := 0; i < len(m.timeSlotHead); i++ {
		m.timeSlotHead[i] = -1
	}

	return m
}
