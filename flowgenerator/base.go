package flowgenerator

import (
	"math"
	"reflect"
	"sync"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
)

const (
	TCP_FIN = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
)

const TCP_FLAG_MASK = 0x3f

const (
	CLOSE_TYPE_UNKNOWN      = iota
	CLOSE_TYPE_FIN                     // 基于TCP FIN判断连接已结束
	CLOSE_TYPE_RST                     // 基于TCP RST判断连接已结束
	CLOSE_TYPE_TIMEOUT                 // 基于相邻网包的间隔时间判断连接已结束
	CLOSE_TYPE_FLOOD                   // 缓存空间不足被迫判断连接已结束
	CLOSE_TYPE_FORCE_REPORT            // 基于连接持续时间超过60秒临时输出
	CLOSE_TYPE_HALF_OPEN    = iota + 1 // timeout时该TCP连接为半开，即三次握手阶段
	CLOSE_TYPE_HALF_CLOSE              // timeout时该TCP连接为半闭，即四次挥手阶段
)

const (
	TIMEOUT_OPENING          = 5 * time.Second
	TIMEOUT_ESTABLISHED      = 300 * time.Second
	TIMEOUT_CLOSING          = 35 * time.Second
	TIMEOUT_ESTABLISHED_RST  = 35 * time.Second
	TIMEOUT_EXPCEPTION       = 5 * time.Second
	TIMEOUT_CLOSED_FIN       = 0
	TIMEOUT_SINGLE_DIRECTION = 5 * time.Second
)

const FLOW_CACHE_CAP = 1024
const HASH_MAP_SIZE uint64 = 1024 * 256
const FLOW_OUT_BUFFER_CAP = 1024 * 64
const TIMOUT_PARALLEL_NUM uint64 = 4

const IN_PORT_FLOW_ID_MASK uint64 = 0xFF000000
const TIMER_FLOW_ID_MASK uint64 = 0x00FFFFFF
const TOTAL_FLOWS_ID_MASK uint64 = 0x0FFFFFFF
const FLOW_LIMIT_NUM uint64 = 1024 * 1024
const FORCE_REPORT_INTERVAL = 60 * time.Second
const REPORT_TOLERANCE = 4 * time.Second

type TimeoutConfig struct {
	Opening         time.Duration
	Established     time.Duration
	Closing         time.Duration
	EstablishedRst  time.Duration
	Exception       time.Duration
	ClosedFin       time.Duration
	SingleDirection time.Duration
}

var defaultTimeoutConfig TimeoutConfig = TimeoutConfig{
	TIMEOUT_OPENING,
	TIMEOUT_ESTABLISHED,
	TIMEOUT_CLOSING,
	TIMEOUT_ESTABLISHED_RST,
	TIMEOUT_EXPCEPTION,
	TIMEOUT_CLOSED_FIN,
	TIMEOUT_SINGLE_DIRECTION,
}

type FlowGeneratorStats struct {
	TotalNumFlows                uint64 `statsd:"total_flow"`
	CurrNumFlows                 uint64 `statsd:"current_flow"`
	NonEmptyFlowCacheNum         int    `statsd:"non_empty_flow_cache_num"`
	MaxFlowCacheLen              int    `statsd:"max_flow_cache_len"`
	cleanRoutineFlowCacheNums    []int
	cleanRoutineMaxFlowCacheLens []int
}

type FastPath struct {
	FlowCacheHashMap

	taggedFlowHandler TaggedFlowHandler
	flowExtraHandler  FlowExtraHandler
}

type PacketHandler struct {
	sync.WaitGroup

	recvBuffer    []interface{}
	processBuffer []interface{}
}

type FlowGenerator struct {
	sync.RWMutex
	TimeoutConfig
	FastPath

	metaPacketHeaderInQueue QueueReader
	flowOutQueue            QueueWriter
	stats                   FlowGeneratorStats
	stateMachineMaster      []map[uint8]*StateValue
	stateMachineSlave       []map[uint8]*StateValue
	servicePortDescriptor   *ServicePortDescriptor
	innerFlowKey            *FlowKey
	packetHandler           *PacketHandler
	forceReportInterval     time.Duration
	minLoopInterval         time.Duration
	flowLimitNum            uint64
	handleRunning           bool
	cleanRunning            bool
	index                   int
	cleanWaitGroup          sync.WaitGroup

	perfCounter         FlowPerfCounter
	metaFlowPerfPool    sync.Pool
	metaFlowPerfBlock   *MetaFlowPerfBlock
	flowPerfBlockCursor int
}

func timeMax(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return b
	}
	return a
}

func timeMin(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (f *FlowGenerator) GetCounter() interface{} {
	nonEmptyFlowCacheNum := 0
	maxFlowCacheLen := 0
	for i := 0; i < int(TIMOUT_PARALLEL_NUM); i++ {
		nonEmptyFlowCacheNum += f.stats.cleanRoutineFlowCacheNums[i]
		if maxFlowCacheLen < f.stats.cleanRoutineMaxFlowCacheLens[i] {
			maxFlowCacheLen = f.stats.cleanRoutineMaxFlowCacheLens[i]
		}
	}
	f.stats.NonEmptyFlowCacheNum = nonEmptyFlowCacheNum
	f.stats.MaxFlowCacheLen = maxFlowCacheLen
	counter := f.stats
	return &counter
}

func (f *FlowGenerator) SetTimeout(timeoutConfig TimeoutConfig) bool {
	if f.handleRunning || f.cleanRunning {
		log.Warning("flow generator is running, timeout info can not be configured")
		return false
	}
	f.TimeoutConfig = timeoutConfig
	f.minLoopInterval = timeoutConfig.minTimeout()
	f.initStateMachineMaster()
	f.initStateMachineSlave()
	return true
}

func (t TimeoutConfig) minTimeout() time.Duration {
	valueOf := reflect.ValueOf(t)
	minTime := time.Duration(math.MaxInt64)
	for i := 0; i < valueOf.NumField(); i++ {
		value := valueOf.Field(i).Interface().(time.Duration)
		if minTime > value && value != 0 {
			minTime = value
		}
	}
	return minTime
}

func (f *FlowGenerator) SetServicePorts(servicePortDescriptor *ServicePortDescriptor) bool {
	if f.handleRunning || f.cleanRunning {
		log.Warning("flow generator is running, service ports list can not be configured")
		return false
	}
	f.servicePortDescriptor = servicePortDescriptor
	return true
}
