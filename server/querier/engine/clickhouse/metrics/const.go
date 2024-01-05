/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package metrics

import (
	"encoding/json"

	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

// 指标量类型
const (
	METRICS_TYPE_UNKNOWN       int = iota // 未被定义的指标量
	METRICS_TYPE_COUNTER                  // 计数，例如字节数、请求数
	METRICS_TYPE_GAUGE                    // 油标，例如活跃连接数、平均包长
	METRICS_TYPE_DELAY                    // 时延，例如各类时延
	METRICS_TYPE_PERCENTAGE               // 百分比，例如异常比例、重传比例
	METRICS_TYPE_QUOTIENT                 // 商值，例如平均包长
	METRICS_TYPE_TAG                      // tag，例如ip
	METRICS_TYPE_ARRAY                    // 数组类型，不支持算子，select时需展开
	METRICS_TYPE_OTHER                    // 只支持 count(_)
	METRICS_TYPE_BOUNDED_GAUGE            // direction_score
)

var METRICS_TYPE_NAME_MAP = map[string]int{
	"counter":       METRICS_TYPE_COUNTER,
	"gauge":         METRICS_TYPE_GAUGE,
	"bounded_gauge": METRICS_TYPE_BOUNDED_GAUGE,
	"delay":         METRICS_TYPE_DELAY,
	"percentage":    METRICS_TYPE_PERCENTAGE,
	"quotient":      METRICS_TYPE_QUOTIENT,
	"tag":           METRICS_TYPE_TAG,
	"other":         METRICS_TYPE_OTHER,
}

var METRICS_ARRAY_NAME_MAP = map[string][]string{
	"flow_log":        []string{"metrics_names", "metrics_values"},
	"ext_metrics":     []string{"metrics_float_names", "metrics_float_values"},
	"deepflow_system": []string{"metrics_float_names", "metrics_float_values"},
}

const (
	FUNCTION_TYPE_UNKNOWN int = iota // 未被定义的算子
	FUNCTION_TYPE_AGG                // 聚合类算子 例：sum、max、min
	FUNCTION_TYPE_RATE               // 速率类算子 例：rate
	FUNCTION_TYPE_MATH               // 算术类算子 例：+ - * /
)

// 指标量类型支持不用拆层的算子的集合
var METRICS_TYPE_UNLAY_FUNCTIONS = map[int][]string{
	METRICS_TYPE_COUNTER:       []string{view.FUNCTION_SUM, view.FUNCTION_AVG},
	METRICS_TYPE_GAUGE:         []string{view.FUNCTION_AVG},
	METRICS_TYPE_BOUNDED_GAUGE: []string{view.FUNCTION_AVG, view.FUNCTION_AAVG, view.FUNCTION_MAX, view.FUNCTION_MIN, view.FUNCTION_LAST},
	METRICS_TYPE_DELAY:         []string{view.FUNCTION_AVG, view.FUNCTION_AAVG, view.FUNCTION_MAX, view.FUNCTION_MIN, view.FUNCTION_LAST},
	METRICS_TYPE_PERCENTAGE:    []string{view.FUNCTION_AVG},
	METRICS_TYPE_QUOTIENT:      []string{view.FUNCTION_AVG},
	METRICS_TYPE_TAG:           []string{view.FUNCTION_UNIQ, view.FUNCTION_UNIQ_EXACT},
	METRICS_TYPE_OTHER:         []string{view.FUNCTION_COUNT},
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

const COUNT_METRICS_NAME = "row"
