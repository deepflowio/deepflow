package flowgenerator

import (
	"container/list"
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

type FlowState int

const (
	FLOW_STATE_RAW FlowState = iota
	FLOW_STATE_OPENING_1
	FLOW_STATE_OPENING_2
	FLOW_STATE_ESTABLISHED
	FLOW_STATE_CLOSING_TX1
	FLOW_STATE_CLOSING_TX2
	FLOW_STATE_CLOSING_RX1
	FLOW_STATE_CLOSING_RX2
	FLOW_STATE_CLOSED
	FLOW_STATE_RESET
	FLOW_STATE_EXCEPTION
)

const (
	TIMEOUT_OPENING          = 5
	TIMEOUT_ESTABLISHED      = 300
	TIMEOUT_CLOSING          = 35
	TIMEOUT_ESTABLISHED_RST  = 35
	TIMEOUT_EXPCEPTION       = 5
	TIMEOUT_CLOSED_FIN       = 0
	TIMEOUT_SINGLE_DIRECTION = 5
)

const FLOW_CACHE_CAP = 1024
const HASH_MAP_SIZE uint64 = 1024 * 2

const IN_PORT_FLOW_ID_MASK uint64 = 0xFF000000
const TIMER_FLOW_ID_MASK uint64 = 0x00FFFFFF
const TOTAL_FLOWS_ID_MASK uint64 = 0x0FFFFFFF

const FLOW_LIMIT_NUM uint64 = 1024 * 1024

const REPORT_TOLERANCE = 4

// unit: second
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

type FlowExtra struct {
	taggedFlow     *TaggedFlow
	metaFlowPerf   *MetaFlowPerf
	flowState      FlowState
	recentTimesSec time.Duration
	timeoutSec     time.Duration
	reversed       bool
}

type FlowGeneratorStats struct {
	TotalNumFlows uint64 `statsd:"total_flow"`
	CurrNumFlows  uint64 `statsd:"current_flow"`
}

type FlowCache struct {
	sync.Mutex

	capacity int
	flowList *list.List
}

type FlowCacheHashMap struct {
	hashMap            []*FlowCache
	mapSize            uint64
	timeoutParallelNum uint64
}

type FastPath struct {
	FlowCacheHashMap
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
	forceReportIntervalSec  time.Duration
	minLoopIntervalSec      time.Duration
	flowLimitNum            uint64
	handleRunning           bool
	cleanRunning            bool
	cleanWaitGroup          sync.WaitGroup
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
	counter := f.stats
	return &counter
}

func (f *FlowGenerator) SetTimeout(timeoutConfig TimeoutConfig) bool {
	if f.handleRunning || f.cleanRunning {
		log.Warning("flow generator is running, timeout info can not be configured")
		return false
	}
	f.TimeoutConfig = timeoutConfig
	f.minLoopIntervalSec = timeoutConfig.minTimeout()
	f.initStateMachineMaster()
	f.initStateMachineSlave()
	return true
}

func (t TimeoutConfig) minTimeout() time.Duration {
	valueOf := reflect.ValueOf(t)
	var minSec time.Duration = 1 << 32 // not max, but enough
	for i := 0; i < valueOf.NumField(); i++ {
		value := valueOf.Field(i).Interface().(time.Duration)
		if minSec > value && value != 0 {
			minSec = value
		}
	}
	return minSec
}
