package flowgenerator

import (
	"math"
	"reflect"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
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
	FLOW_ACTION = ACTION_FLOW_COUNTING | ACTION_FLOW_STORING | ACTION_TCP_FLOW_PERF_COUNTING |
		ACTION_FLOW_MISC_COUNTING | ACTION_GEO_POSITIONING
	PACKET_ACTION = ACTION_PACKET_COUNTING
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

const (
	MAC_MATCH_NONE = 0x00 // don't match any mac
	MAC_MATCH_DST  = 0x01 // ignore src and only match dst mac
	MAC_MATCH_SRC  = 0x10 // ignore dst and only match src mac
	MAC_MATCH_ALL  = 0x11 // match all macs
)

const QUEUE_BATCH_SIZE = 4096

const (
	THREAD_FLOW_ID_MASK  uint64 = 0xFF000000
	TIMER_FLOW_ID_MASK   uint64 = 0x00FFFFFF
	COUNTER_FLOW_ID_MASK uint64 = 0x0FFFFFFF
)

const SECOND_COUNT_PER_MINUTE = 60

// configurations for base flow generator, read only
var (
	flowGeneratorCount uint64
	hashMapSize        uint64
	packetDelay        time.Duration
	ignoreTorMac       bool
	ignoreL2End        bool
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

	minTimeout time.Duration
	maxTimeout time.Duration
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

type FlowGenerator struct {
	flowMap *FlowMap

	inputQueue   QueueReader // 注意设置不低于_FLOW_STAT_INTERVAL的FlushIndicator
	pcapAppQueue QueueWriter
	running      bool
	index        int
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

func SetTimeout(timeout TimeoutConfig) {
	openingTimeout = timeout.Opening
	establishedTimeout = timeout.Established
	closingTimeout = timeout.Closing
	establishedRstTimeout = timeout.EstablishedRst
	exceptionTimeout = timeout.Exception
	closedFinTimeout = timeout.ClosedFin
	singleDirectionTimeout = timeout.SingleDirection
	minTimeout, maxTimeout = timeout.timeoutRange()
	log.Infof("flow generator timeout config: %+v", timeout)
}

func SetFlowGenerator(cfg config.Config) {
	flowGeneratorCount = uint64(cfg.Queue.PacketQueueCount)
	hashMapSize = cfg.FlowGenerator.HashMapSize
	packetDelay = cfg.FlowGenerator.PacketDelay
	ignoreTorMac = cfg.FlowGenerator.IgnoreTorMac
	ignoreL2End = cfg.FlowGenerator.IgnoreL2End

	innerFlowGeo = newFlowGeo()
}

func (t TimeoutConfig) timeoutRange() (time.Duration, time.Duration) {
	valueOf := reflect.ValueOf(t)
	minTime := time.Duration(math.MaxInt64)
	maxTime := time.Duration(0)
	for i := 0; i < valueOf.NumField(); i++ {
		value := valueOf.Field(i).Interface().(time.Duration)
		if minTime > value && value != 0 {
			minTime = value
		}
		if maxTime < value {
			maxTime = value
		}
	}
	return minTime, maxTime
}
