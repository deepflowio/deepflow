package metric

import (
	"encoding/json"
	"metaflow/querier/engine/clickhouse/view"
)

// 指标量类型
const (
	METRIC_TYPE_UNKNOWN    int = iota // 未被定义的指标量
	METRIC_TYPE_COUNTER               // 计数，例如字节数、请求数
	METRIC_TYPE_GAUGE                 // 油标，例如活跃连接数、平均包长
	METRIC_TYPE_DELAY                 // 时延，例如各类时延
	METRIC_TYPE_PERCENTAGE            // 百分比，例如异常比例、重传比例
	METRIC_TYPE_QUOTIENT              // 商值，例如平均包长
	METRIC_TYPE_TAG                   // tag，例如ip
)

var METRIC_TYPE_NAME_MAP = map[string]int{
	"counter":    METRIC_TYPE_COUNTER,
	"gauge":      METRIC_TYPE_GAUGE,
	"delay":      METRIC_TYPE_DELAY,
	"percentage": METRIC_TYPE_PERCENTAGE,
	"quotient":   METRIC_TYPE_QUOTIENT,
	"tag":        METRIC_TYPE_TAG,
}

const (
	FUNCTION_TYPE_UNKNOWN int = iota // 未被定义的算子
	FUNCTION_TYPE_AGG                // 聚合类算子 例：sum、max、min
	FUNCTION_TYPE_RATE               // 速率类算子 例：rate
	FUNCTION_TYPE_MATH               // 算术类算子 例：+ - * /
)

// 指标量类型支持不用拆层的算子的集合
var METRIC_TYPE_UNLAY_FUNCTIONS = map[int][]string{
	METRIC_TYPE_COUNTER:    []string{view.FUNCTION_SUM},
	METRIC_TYPE_GAUGE:      []string{},
	METRIC_TYPE_DELAY:      []string{view.FUNCTION_AVG, view.FUNCTION_MAX, view.FUNCTION_MIN},
	METRIC_TYPE_PERCENTAGE: []string{},
	METRIC_TYPE_QUOTIENT:   []string{},
	METRIC_TYPE_TAG:        []string{view.FUNCTION_UNIQ, view.FUNCTION_UNIQ_EXACT},
}

const (
	L4_FLOW_LOG_CATEGORY_L3_TRAFFIC            = "l3-traffic-flow-log"
	L4_FLOW_LOG_CATEGORY_L4_LATENCY            = "l4-latency-flow-log"
	L4_FLOW_LOG_CATEGORY_L4_PERFORMANCE        = "l4-performance-flow-log"
	L4_FLOW_LOG_CATEGORY_L4_TRAFFIC            = "l4-traffic-flow-log"
	L4_FLOW_LOG_CATEGORY_L4_EXCEPTION          = "l4-exception-flow-log"
	L4_FLOW_LOG_CATEGORY_L7_PERFORMANCE        = "l7-performance-flow-log"
	L4_FLOW_LOG_CATEGORY_LOG_COUNT             = "log-count-flow-log"
	L4_FLOW_LOG_CATEGORY_TRAFFIC_PROPERTY_PEER = "traffic-property-peer"
)

const (
	FLOW_LOG_TYPE_REQUEST     = 0
	FLOW_LOG_TYPE_RESPONSE    = 1
	FLOW_LOG_TYPE_SESSION     = 2
	FLOW_LOG_EXCEPTION_SERVER = 3
	FLOW_LOG_EXCEPTION_CLIENT = 4
)
const (
	FLOW_LOG_CLOSE_TYPE_TCP_SERVER_RST       = 2  // 服务端重置
	FLOW_LOG_CLOSE_TYPE_TIMEOUT              = 3  // 连接超时
	FLOW_LOG_CLOSE_TYPE_FORCED_REPORT        = 5  // 周期上报
	FLOW_LOG_CLOSE_TYPE_CLIENT_SYN_REPEAT    = 7  // 建连-客户端syn结束
	FLOW_LOG_CLOSE_TYPE_SERVER_HALF_CLOSE    = 8  // 服务端半关
	FLOW_LOG_CLOSE_TYPE_TCP_CLIENT_RST       = 9  // 客户端重置
	FLOW_LOG_CLOSE_TYPE_SERVER_SYNACK_REPEAT = 10 // 建连-服务端syn结束
	FLOW_LOG_CLOSE_TYPE_CLIENT_HALF_CLOSE    = 11 // 客户端半关
	FLOW_LOG_CLOSE_TYPE_CLIENT_PORT_REUSE    = 13 // 建连-客户端端口复用
	FLOW_LOG_CLOSE_TYPE_SERVER_RST           = 15 // 服务端直接重置
	FLOW_LOG_CLOSE_TYPE_SERVER_QUEUE_LACK    = 17 // 服务端队列溢出
	FLOW_LOG_CLOSE_TYPE_CLIENT_ESTABLISH_RST = 18 // 客户端其他重置
	FLOW_LOG_CLOSE_TYPE_SERVER_ESTABLISH_RST = 19 // 服务端其他重置
)

const FLOW_LOG_IS_NEW_FLOW = 1

// 传输失败次数 = FLOW_LOG_CLOSE_TYPE in
// [客户端/服务端重置, 服务端队列溢出, 客户端/服务端半关, 连接超时]
var FLOW_LOG_CLOSE_TYPE_EXCEPTION, _ = json.Marshal([]int{
	FLOW_LOG_CLOSE_TYPE_TCP_SERVER_RST, FLOW_LOG_CLOSE_TYPE_TCP_CLIENT_RST,
	FLOW_LOG_CLOSE_TYPE_SERVER_QUEUE_LACK, FLOW_LOG_CLOSE_TYPE_TIMEOUT,
	FLOW_LOG_CLOSE_TYPE_SERVER_HALF_CLOSE, FLOW_LOG_CLOSE_TYPE_CLIENT_HALF_CLOSE,
})

// 重置次数 = FLOW_LOG_CLOSE_TYPE in
// [客户端/服务端其他重置, 服务端直接重置, 客户端/服务端重置]
var FLOW_LOG_CLOSE_TYPE_RST, _ = json.Marshal([]int{
	FLOW_LOG_CLOSE_TYPE_CLIENT_ESTABLISH_RST, FLOW_LOG_CLOSE_TYPE_SERVER_ESTABLISH_RST,
	FLOW_LOG_CLOSE_TYPE_SERVER_RST, FLOW_LOG_CLOSE_TYPE_TCP_SERVER_RST, FLOW_LOG_CLOSE_TYPE_TCP_CLIENT_RST,
})

// 建连失败次数= FLOW_LOG_CLOSE_TYPE in
// [建连-客户端/服务端syn结束, 建连-客户端端口复用, 服务端直接重置,
// 客户端/服务端其他重置]
var FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION, _ = json.Marshal([]int{
	FLOW_LOG_CLOSE_TYPE_CLIENT_PORT_REUSE, FLOW_LOG_CLOSE_TYPE_CLIENT_SYN_REPEAT,
	FLOW_LOG_CLOSE_TYPE_SERVER_SYNACK_REPEAT, FLOW_LOG_CLOSE_TYPE_SERVER_RST,
	FLOW_LOG_CLOSE_TYPE_CLIENT_ESTABLISH_RST, FLOW_LOG_CLOSE_TYPE_SERVER_ESTABLISH_RST,
})

// 建连失败次数-客户端
var FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION_CLIENT, _ = json.Marshal([]int{
	FLOW_LOG_CLOSE_TYPE_CLIENT_PORT_REUSE, FLOW_LOG_CLOSE_TYPE_CLIENT_SYN_REPEAT,
	FLOW_LOG_CLOSE_TYPE_CLIENT_ESTABLISH_RST,
})

// 建连失败次数-服务端
var FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION_SERVER, _ = json.Marshal([]int{
	FLOW_LOG_CLOSE_TYPE_SERVER_SYNACK_REPEAT, FLOW_LOG_CLOSE_TYPE_SERVER_RST,
	FLOW_LOG_CLOSE_TYPE_SERVER_ESTABLISH_RST,
})
