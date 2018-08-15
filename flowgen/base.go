package flowgen

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"

	"gitlab.x.lan/yunshan/droplet/flowperf"
)

const (
	TCP_FIN = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
)

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

// FIXME: need to add state of client and server
const (
	FLOW_STATE_EXCEPTION = iota
	FLOW_STATE_OPENING
	FLOW_STATE_ESTABLISHED
	FLOW_STATE_CLOSING
	FLOW_STATE_CLOSED
)

const (
	TIMEOUT_OPENING         = 5
	TIMEOUT_ESTABLISHED     = 30 * 60
	TIMEOUT_CLOSING         = 30
	TIMEOUT_ESTABLISHED_RST = 30
	TIMEOUT_EXPCEPTION      = 5
	TIMEOUT_CLOSED_FIN      = 0
)

const FLOW_CACHE_CAP = 1024
const HASH_MAP_SIZE uint64 = 1024 * 2

const IN_PORT_FLOW_ID_MASK uint64 = 0xFF000000
const TIMER_FLOW_ID_MASK uint64 = 0x00FFFFFF
const TOTAL_FLOWS_ID_MASK uint64 = 0x0FFFFFFF

const FLOW_LIMIT_NUM uint64 = 1024 * 1024

// unit: second
type TimeoutConfig struct {
	Opening        time.Duration
	Established    time.Duration
	Closing        time.Duration
	EstablishedRst time.Duration
	Exception      time.Duration
	ClosedFin      time.Duration
}

var innerTimeoutConfig = TimeoutConfig{
	TIMEOUT_OPENING,
	TIMEOUT_ESTABLISHED,
	TIMEOUT_CLOSING,
	TIMEOUT_ESTABLISHED_RST,
	TIMEOUT_EXPCEPTION,
	TIMEOUT_CLOSED_FIN,
}

type FlowExtra struct {
	taggedFlow     *TaggedFlow
	metaFlowPerf   *flowperf.MetaFlowPerf
	flowState      FlowState
	recentTimesSec time.Duration
	timeoutSec     time.Duration
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
	size               uint64
	timeoutParallelNum uint64
}

type FastPath struct {
	FlowCacheHashMap
}

type FlowGenerator struct {
	sync.RWMutex

	fastPath                FastPath
	metaPacketHeaderInQueue QueueReader
	flowOutQueue            QueueWriter
	stats                   FlowGeneratorStats
	forceReportIntervalSec  time.Duration
	minLoopIntervalSec      time.Duration
	flowLimitNum            uint64
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

func TaggedFlowString(f *TaggedFlow) string {
	return fmt.Sprintf("%+v\n%+v", *f, *f.TcpPerfStats)
}

func (f *FlowGenerator) GetCounter() interface{} {
	counter := f.stats
	return &counter
}

func SetTimeout(timeoutConfig TimeoutConfig) {
	innerTimeoutConfig = timeoutConfig
}
