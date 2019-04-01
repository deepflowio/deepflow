package flowgenerator

import (
	"math"
	"reflect"
	"sync"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet/config"
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
	TIMEOUT_OPENING          = 5 * time.Second
	TIMEOUT_ESTABLISHED      = 300 * time.Second
	TIMEOUT_CLOSING          = 35 * time.Second
	TIMEOUT_ESTABLISHED_RST  = 35 * time.Second
	TIMEOUT_EXPCEPTION       = 5 * time.Second
	TIMEOUT_CLOSED_FIN       = 0
	TIMEOUT_SINGLE_DIRECTION = 5 * time.Second
)

const (
	MAC_MATCH_NONE = 0x00 // don't match any mac
	MAC_MATCH_DST  = 0x01 // ignore src and only match dst mac
	MAC_MATCH_SRC  = 0x10 // ignore dst and only match src mac
	MAC_MATCH_ALL  = 0x11 // match all macs
)

const FLOW_CACHE_CAP = 1024
const HASH_MAP_SIZE uint64 = 1024 * 256
const FLOW_OUT_BUFFER_CAP = 1024 * 2
const TIMEOUT_CLEANER_COUNT uint64 = 4

const IN_PORT_FLOW_ID_MASK uint64 = 0xFF000000
const TIMER_FLOW_ID_MASK uint64 = 0x00FFFFFF
const TOTAL_FLOWS_ID_MASK uint64 = 0x0FFFFFFF
const FLOW_LIMIT_NUM uint64 = 1024 * 1024
const FLOW_CLEAN_INTERVAL = time.Second
const FORCE_REPORT_INTERVAL = 60 * time.Second
const MIN_FORCE_REPORT_TIME = 5 * time.Second
const REPORT_TOLERANCE = 4 * time.Second
const SECOND_COUNT_PER_MINUTE = 60

// configurations for base flow generator, read only
var (
	flowGeneratorCount   uint64
	timeoutCleanerCount  uint64
	hashMapSize          uint64
	forceReportInterval  time.Duration
	flowCleanInterval    time.Duration
	reportTolerance      time.Duration
	ignoreTorMac         bool
	ignoreL2End          bool
	portStatsInterval    time.Duration
	portStatsSrcEndCount int
	portStatsTimeout     time.Duration
)

// configurations for timeout, read only
var (
	openingTimeout         time.Duration
	establishedTimeout     time.Duration
	closingTimeout         time.Duration
	establishedRstTimeout  time.Duration
	exceptionTimeout       time.Duration
	closedFinTimeout       time.Duration
	singleDirectionTimeout time.Duration
	minTimeout             time.Duration
)

// timeout config for outer user
type TimeoutConfig struct {
	Opening         time.Duration
	Established     time.Duration
	Closing         time.Duration
	EstablishedRst  time.Duration
	Exception       time.Duration
	ClosedFin       time.Duration
	SingleDirection time.Duration
}

type FlowGeneratorStats struct {
	TotalNumFlows                uint64 `statsd:"total_flow"`
	CurrNumFlows                 int32  `statsd:"current_flow"`
	FloodDropPackets             uint64 `statsd:"flood_drop_packet"`
	NonEmptyFlowCacheNum         int    `statsd:"non_empty_flow_cache_num"`
	MaxFlowCacheLen              int    `statsd:"max_flow_cache_len"`
	cleanRoutineFlowCacheNums    []int
	cleanRoutineMaxFlowCacheLens []int
}

type PacketHandler struct {
	sync.WaitGroup

	recvBuffer    []interface{}
	processBuffer []interface{}
}

type FlowGenerator struct {
	FlowCacheHashMap
	FlowGeo

	metaPacketHeaderInQueue MultiQueueReader
	flowOutQueue            QueueWriter
	stats                   FlowGeneratorStats
	stateMachineMaster      []map[uint8]*StateValue
	stateMachineSlave       []map[uint8]*StateValue
	packetHandler           *PacketHandler
	bufferSize              int
	flowLimitNum            int32
	handleRunning           bool
	cleanRunning            bool
	index                   int
	cleanWaitGroup          sync.WaitGroup

	perfCounter FlowPerfCounter
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

func getBitmap(now time.Duration) uint64 {
	return 1 << uint64((now/time.Second+1)%SECOND_COUNT_PER_MINUTE)
}

func toTimestamp(t time.Time) time.Duration {
	return time.Duration(t.UnixNano())
}

func (f *FlowGenerator) GetCounter() interface{} {
	nonEmptyFlowCacheNum := 0
	maxFlowCacheLen := 0
	for i := 0; i < int(timeoutCleanerCount); i++ {
		nonEmptyFlowCacheNum += f.stats.cleanRoutineFlowCacheNums[i]
		if maxFlowCacheLen < f.stats.cleanRoutineMaxFlowCacheLens[i] {
			maxFlowCacheLen = f.stats.cleanRoutineMaxFlowCacheLens[i]
		}
	}
	f.stats.NonEmptyFlowCacheNum = nonEmptyFlowCacheNum
	f.stats.MaxFlowCacheLen = maxFlowCacheLen
	counter := f.stats
	f.stats.FloodDropPackets = 0
	return &counter
}

func (f *FlowGenerator) Closed() bool {
	return false // FIXME: never close?
}

func SetTimeout(timeout TimeoutConfig) {
	openingTimeout = timeout.Opening
	establishedTimeout = timeout.Established
	closingTimeout = timeout.Closing
	establishedRstTimeout = timeout.EstablishedRst
	exceptionTimeout = timeout.Exception
	closedFinTimeout = timeout.ClosedFin
	singleDirectionTimeout = timeout.SingleDirection
	minTimeout = timeout.minTimeout()
	log.Infof("flow generator timeout config: %+v", timeout)
	if flowCleanInterval > minTimeout {
		log.Warningf("flow-clean-interval (%v) is too large, may cause inaccurate flow time", flowCleanInterval)
	}
}

func SetFlowGenerator(cfg config.Config) {
	flowGeneratorCount = uint64(cfg.Queue.FlowGeneratorQueueCount)
	forceReportInterval = cfg.FlowGenerator.ForceReportInterval
	flowCleanInterval = cfg.FlowGenerator.FlowCleanInterval
	timeoutCleanerCount = cfg.FlowGenerator.TimeoutCleanerCount
	hashMapSize = cfg.FlowGenerator.HashMapSize
	reportTolerance = cfg.FlowGenerator.ReportTolerance
	ignoreTorMac = cfg.FlowGenerator.IgnoreTorMac
	ignoreL2End = cfg.FlowGenerator.IgnoreL2End
	portStatsInterval = cfg.FlowGenerator.PortStats.Interval
	portStatsSrcEndCount = cfg.FlowGenerator.PortStats.SrcEndCount
	portStatsTimeout = cfg.FlowGenerator.PortStats.Timeout

	innerTcpSMA = make([]*ServiceManager, flowGeneratorCount)
	innerUdpSMA = make([]*ServiceManager, flowGeneratorCount)
	for i := uint64(0); i < flowGeneratorCount; i++ {
		innerTcpSMA[i] = NewServiceManager(32 * 1024)
		innerUdpSMA[i] = NewServiceManager(32 * 1024)
	}
	innerFlowGeo = newFlowGeo()
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
