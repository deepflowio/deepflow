package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
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

	FLOW_STATE_MAX
)

type FlowExtra struct {
	taggedFlow   *TaggedFlow
	metaFlowPerf *MetaFlowPerf
	minArrTime   time.Duration
	recentTime   time.Duration // 最近一个Packet的时间戳
	timeout      time.Duration // 相对超时时间
	flowState    FlowState
	reported     bool
	reversed     bool

	packetInTick  bool // 当前包统计周期（目前是自然秒）是否有包
	packetInCycle bool // 当前流统计周期（目前是自然分）是否有包
}
