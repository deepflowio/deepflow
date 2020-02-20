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

type PolicyGetter = func(packet *datatype.MetaPacket, threadIndex int)

// 注意：不是线程安全的
type FlowMap struct {
	FlowGeo
	ringBuffer       []flowMapNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32              // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32              // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots      int32 // 上取整至2^N，哈希桶个数
	timeWindowSize int64 // 上取整至2^N，环形时间桶的槽位个数

	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]
	timeSlotHead []int32 // 时间桶，含义与 hashSlotHead 类似

	startTime       time.Duration // 时间桶中的最早时间
	startTimeInUnit int64         // 时间桶中的最早时间，以_TIME_SLOT_UNIT为单位
	packetDelay     time.Duration // Packet到达的最大Delay

	packetStatOutputBuffer []interface{} // 包统计信息输出的缓冲区
	flowStatOutputBuffer   []interface{} // 流统计信息输出的缓冲区
	packetAppQueue         queue.QueueWriter
	flowAppQueue           queue.QueueWriter
	lastQueueFlush         time.Duration
	flowAppQueueFlush      time.Duration
	flushInterval          time.Duration

	stateMachineMaster [FLOW_STATE_MAX][TCP_FLAG_MASK + 1]*StateValue
	stateMachineSlave  [FLOW_STATE_MAX][TCP_FLAG_MASK + 1]*StateValue
	tcpServiceTable    *ServiceTable
	udpServiceTable    *ServiceTable
	tcpServiceTable6   *ServiceTable6
	udpServiceTable6   *ServiceTable6
	policyGetter       PolicyGetter
	srcServiceKey      []byte
	dstServiceKey      []byte

	capacity  int    // 最大容纳的Flow个数
	size      int    // 当前容纳的Flow个数
	width     int    // 当前哈希桶中的最长冲突链长度
	totalFlow uint64 // 用于生成当前分析器上全局唯一的FlowID
	id        int    // 在性能监控数据中标识不同的FlowMap

	counter     *FlowMapCounter
	perfCounter FlowPerfCounter
}

type FlowMapCounter struct {
	New       uint64 `statsd:"new,counter"`
	Closed    uint64 `statsd:"closed,counter"`
	Size      uint32 `statsd:"size,gauge"`
	MaxBucket uint32 `statsd:"max_bucket,gauge"`

	DropByCapacity   uint64 `statsd:"drop_by_capacity,counter"`
	DropBeforeWindow uint64 `statsd:"drop_before_window,counter"`
}

func (m *FlowMap) GetCounter() interface{} {
	counter := &FlowMapCounter{}
	m.counter, counter = counter, m.counter

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
	hashSlot := m.compressHash(hash)
	node.hash = hash
	node.hashListNext = m.hashSlotHead[hashSlot]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hashSlot] = nodeIndex
}

func (m *FlowMap) pushNodeToTimeList(node *flowMapNode, nodeIndex int32, timeInUnit int64) {
	timeSlot := timeInUnit & (m.timeWindowSize - 1)
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
		m.hashSlotHead[m.compressHash(node.hash)] = newNext
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
		m.timeSlotHead[node.timeInUnit&(m.timeWindowSize-1)] = newNext
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
	m.counter.Closed++
}

func (m *FlowMap) changeTimeSlot(node *flowMapNode, nodeIndex int32, timeInUnit int64) {
	if node.timeInUnit != timeInUnit {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入新的时间链表
		m.pushNodeToTimeList(node, nodeIndex, timeInUnit)
	}
}

func (m *FlowMap) flushQueue(now time.Duration) {
	if now-m.lastQueueFlush > m.flushInterval {
		if len(m.packetStatOutputBuffer) > 0 {
			m.packetAppQueue.Put(m.packetStatOutputBuffer...)
			m.packetStatOutputBuffer = m.packetStatOutputBuffer[:0]
		}
		if len(m.flowStatOutputBuffer) > 0 {
			m.flowAppQueue.Put(m.flowStatOutputBuffer...)
			m.flowStatOutputBuffer = m.flowStatOutputBuffer[:0]
		}
		m.lastQueueFlush = now
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

func (m *FlowMap) removeAndOutput(node *flowMapNode, nodeIndex int32, timestamp time.Duration, meta *datatype.MetaPacket) {
	flowExtra := &node.flowExtra
	taggedFlow := flowExtra.taggedFlow

	// 统计数据输出前矫正流方向
	m.updateFlowDirection(flowExtra, meta)

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

func (m *FlowMap) copyAndOutput(node *flowMapNode, timestamp time.Duration, meta *datatype.MetaPacket) {
	flowExtra := &node.flowExtra
	taggedFlow := flowExtra.taggedFlow
	output := false

	// 如果timestamp和上一个包不在一个_PACKET_STAT_INTERVAL，输出Packet统计信息并清零
	if flowExtra.packetInTick && (timestamp >= taggedFlow.PacketStatTime+_PACKET_STAT_INTERVAL || timestamp < taggedFlow.PacketStatTime) {
		if taggedFlow.PolicyData.ActionFlags&PACKET_ACTION != 0 {
			output = true
			m.updateFlowDirection(flowExtra, meta) // 每个包统计数据输出前矫正流方向

			flowExtra.cow |= FLOW_COW_PACKET_STAT
			taggedFlow.AddReferenceCount()
			m.pushToPacketStatsQueue(taggedFlow)
		} else {
			flowExtra.resetPacketStatInfo() // 清零包统计数据
		}
	}

	// 如果timestamp和上一个包不在一个_FLOW_STAT_INTERVAL，输出Flow统计信息并清零
	// 注意：流统计需要考虑包到达时间的延时容差，即若timestamp落在更靠前的统计周期内时，数据仍然计入当前统计周期
	if timestamp >= taggedFlow.FlowStatTime+_FLOW_STAT_INTERVAL {
		flowExtra.setEndTimeAndDuration(taggedFlow.FlowStatTime + _FLOW_STAT_INTERVAL)
		if taggedFlow.PolicyData.ActionFlags&FLOW_ACTION != 0 {
			if !output {
				m.updateFlowDirection(flowExtra, meta) // 每个流统计数据输出前矫正流方向
			}

			flowExtra.cow |= FLOW_COW_FLOW_STAT
			taggedFlow.AddReferenceCount()
			taggedFlow.CloseType = datatype.CloseTypeForcedReport
			taggedFlow.TcpPerfStats = copyAndResetPerfData(flowExtra.metaFlowPerf, flowExtra.reversed, &m.perfCounter)
			m.pushToFlowStatsQueue(taggedFlow)
		} else {
			resetPerfData(flowExtra.metaFlowPerf)
			flowExtra.resetFlowStatInfo() // 清零流统计数据
		}
	}
}

func (m *FlowMap) flowCopyOnWrite(flowExtra *FlowExtra) {
	if flowExtra.cow == 0 {
		return
	}

	taggedFlow := flowExtra.taggedFlow
	if taggedFlow.GetReferenceCount() > 1 {
		flowExtra.taggedFlow = datatype.CloneTaggedFlow(taggedFlow)
		datatype.ReleaseTaggedFlow(taggedFlow)
	}
	if flowExtra.cow&FLOW_COW_PACKET_STAT != 0 {
		flowExtra.resetPacketStatInfo() // 清零包统计数据
	}
	if flowExtra.cow&FLOW_COW_FLOW_STAT != 0 {
		flowExtra.resetFlowStatInfo() // 清零流统计数据
	}
	flowExtra.cow = 0
}

// 外部直接调用InjectFlushTicker时，timestamp需设置为0表示使用系统当前时间。
// 返回值为false表示传入时间没有落在窗口中。
func (m *FlowMap) InjectFlushTicker(timestamp time.Duration) bool {
	if timestamp == 0 { // 仅在低负载时使用系统时间（而非包的时间）推动时间窗口
		timestamp = time.Duration(time.Now().UnixNano())
	} else {
		if timestamp < m.startTime {
			m.counter.DropBeforeWindow++
			return false
		}
	}

	if timestamp-m.packetDelay-_TIME_SLOT_UNIT < m.startTime { // FlowMap的时间窗口无法推动
		return true
	}

	nextStartTimeInUnit := int64((timestamp - m.packetDelay) / _TIME_SLOT_UNIT)
	m.startTime = time.Duration(nextStartTimeInUnit) * _TIME_SLOT_UNIT
	timestamp = m.startTime - 1

	next := int32(0)
	for timeInUnit := m.startTimeInUnit; timeInUnit < nextStartTimeInUnit; timeInUnit++ { // 扫描过期的时间槽
		timeHead := m.timeSlotHead[timeInUnit&(m.timeWindowSize-1)]
		for this := timeHead; this != -1; this = next { // 扫描特定时间点的链表
			node := m.getNode(this)
			next = node.timeListNext // node可能发生删除或移动，缓存next

			// Copy On Write
			m.flowCopyOnWrite(&node.flowExtra)

			// 若Flow已经超时，直接输出
			timeout := node.flowExtra.recentTime + node.flowExtra.timeout
			if timestamp >= timeout {
				m.removeAndOutput(node, this, timeout, nil)
				// 若next正好指向删掉节点之前的buffer头部，需要将next矫正至node本身
				// 因为删除机制会将被删除的节点交换至buffer头部进行删除
				if next == m.decIndex(m.bufferStartIndex) {
					next = this
				}
				continue
			}
			flowStatTime := node.flowExtra.taggedFlow.FlowStatTime

			// 输出未超时Flow的统计信息
			m.copyAndOutput(node, timestamp, nil)

			// 若流统计信息已输出，将节点移动至下一个流统计的时间，或者最终超时的时间
			nextListTime := flowStatTime + _FLOW_STAT_INTERVAL
			if nextListTime <= timestamp {
				nextListTime += _FLOW_STAT_INTERVAL
			}
			if nextListTime > timeout {
				nextListTime = timeout
			}
			m.changeTimeSlot(node, this, int64(nextListTime/_TIME_SLOT_UNIT))
		}
	}

	m.startTimeInUnit = nextStartTimeInUnit
	m.flushQueue(timestamp)
	return true
}

func (m *FlowMap) updateNode(node *flowMapNode, nodeIndex int32, meta *datatype.MetaPacket) {
	flowExtra := &node.flowExtra

	// 1. 输出上一个统计周期的统计信息
	m.flowCopyOnWrite(flowExtra)
	m.copyAndOutput(node, meta.Timestamp, meta)

	// 2. 更新Flow状态，判断是否已结束
	m.flowCopyOnWrite(flowExtra)
	if meta.Protocol == layers.IPProtocolTCP {
		flowClosed := m.updateTcpFlow(flowExtra, meta)
		if m.checkIfDoFlowPerf(flowExtra) {
			serverToClient := (meta.Direction == datatype.SERVER_TO_CLIENT)
			flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed == serverToClient, flowExtra, &m.perfCounter)
		}
		if flowClosed {
			m.removeAndOutput(node, nodeIndex, meta.Timestamp, meta)
			return
		}
	} else if meta.Protocol == layers.IPProtocolUDP {
		m.updateUdpFlow(flowExtra, meta)
	} else if meta.EthType != layers.EthernetTypeIPv4 {
		m.updateEthOthersFlow(flowExtra, meta)
	} else {
		m.updateIpOthersFlow(flowExtra, meta)
	}

	// 3. 由于包、流统计信息已输出，将节点移动至包对应的时间槽
	m.changeTimeSlot(node, nodeIndex, int64(meta.Timestamp/_TIME_SLOT_UNIT))
}

func (m *FlowMap) newNode(meta *datatype.MetaPacket, hash uint64) bool {
	// buffer空间检查
	if m.size >= m.capacity {
		m.counter.DropByCapacity++
		return false
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = flowMapNodeBlockPool.Get().(flowMapNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++
	m.totalFlow++
	m.counter.New++

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
	return true
}

func (m *FlowMap) InjectMetaPacket(block *datatype.MetaPacketBlock) {
	if block.Count == 0 {
		return
	}
	// 使用block中的最后一个包滑动时间窗口，一个block一定在trident发送的一个压缩包头中且递增，时间最大只跨越1秒
	if !m.InjectFlushTicker(block.Metas[block.Count-1].Timestamp) {
		// 补充由于超时导致未查询策略，用于其它流程（如PCAP存储）
		for i := uint8(0); i < block.Count; i++ {
			m.policyGetter(&block.Metas[i], m.id)
		}
		return
	}

	for i := uint8(0); i < block.Count; i++ {
		meta := &block.Metas[i]
		hash := uint64(0)
		if meta.EthType != layers.EthernetTypeIPv4 && meta.EthType != layers.EthernetTypeIPv6 {
			hash = m.getEthOthersQuinTupleHash(meta)
		} else {
			hash = m.getQuinTupleHash(meta)
		}
		if !m.injectMetaPacket(hash, meta) { // 补充由于超限导致未查询策略，用于其它流程（如PCAP存储）
			m.policyGetter(meta, m.id)
		}
	}
}

func (m *FlowMap) injectMetaPacket(hash uint64, meta *datatype.MetaPacket) bool {
	// 查找对应Flow所在的节点
	width := 0
	next := int32(0)
	hashHead := m.hashSlotHead[m.compressHash(hash)]
	for this := hashHead; this != -1; this = next {
		node := m.getNode(this)
		next = node.hashListNext // node可能发生删除或移动，缓存next
		width++

		if node.hash == hash && node.flowExtra.Match(meta) {
			m.updateNode(node, this, meta)
			next = -1 // 由于会发生节点删除，此时next不再有效

			if m.width < width {
				m.width = width
			}
			return true
		}
	}
	if m.width < width+1 {
		m.width = width + 1
	}

	// 未找到Flow，需要插入新的节点
	return m.newNode(meta, hash)
}

func minPowerOfTwo(v int) (int, int) {
	for i := 0; i < 30; i++ {
		if v <= 1<<i {
			return 1 << i, i
		}
	}
	return 1, 0
}

func (m *FlowMap) compressHash(hash uint64) int32 {
	return int32(hash) & (m.hashSlots - 1)
}

func (m *FlowMap) initTimeWindow() {
	// startTimeInUnit的计算中减去time.Second避免UT失败
	m.startTimeInUnit = int64((time.Duration(time.Now().UnixNano()) - m.packetDelay - time.Second) / _TIME_SLOT_UNIT)
	m.startTime = time.Duration(m.startTimeInUnit) * _TIME_SLOT_UNIT
}

func NewFlowMap(hashSlots, capacity, id int, timeWindow, packetDelay, flushInterval time.Duration, packetAppQueue, flowAppQueue queue.QueueWriter, policyGetter PolicyGetter) *FlowMap {
	hashSlots, _ = minPowerOfTwo(hashSlots)
	if timeWindow < _FLOW_STAT_INTERVAL {
		timeWindow = _FLOW_STAT_INTERVAL
	}
	timeWindowSize, _ := minPowerOfTwo(int((timeWindow + packetDelay + _TIME_SLOT_UNIT) / _TIME_SLOT_UNIT))

	m := &FlowMap{
		FlowGeo:                innerFlowGeo,
		ringBuffer:             make([]flowMapNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:              int32(hashSlots),
		timeWindowSize:         int64(timeWindowSize),
		hashSlotHead:           make([]int32, hashSlots),
		timeSlotHead:           make([]int32, timeWindowSize),
		packetDelay:            packetDelay,
		packetStatOutputBuffer: make([]interface{}, 0, 256),
		flowStatOutputBuffer:   make([]interface{}, 0, 256),
		packetAppQueue:         packetAppQueue,
		flowAppQueue:           flowAppQueue,
		flushInterval:          flushInterval,
		tcpServiceTable:        NewServiceTable("tcp", id, hashSlots, capacity),
		udpServiceTable:        NewServiceTable("udp", id, hashSlots, capacity),
		tcpServiceTable6:       NewServiceTable6("tcp", id, hashSlots, capacity),
		udpServiceTable6:       NewServiceTable6("udp", id, hashSlots, capacity),
		policyGetter:           policyGetter,
		srcServiceKey:          make([]byte, _KEY_LEN),
		dstServiceKey:          make([]byte, _KEY_LEN),
		id:                     id,
		capacity:               capacity,
		counter:                &FlowMapCounter{},
		perfCounter:            NewFlowPerfCounter(),
	}
	m.initTimeWindow()
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
