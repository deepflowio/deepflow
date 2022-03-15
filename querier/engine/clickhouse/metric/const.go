package metric

import (
	"metaflow/querier/engine/clickhouse/view"
)

// 指标量类型
const (
	METRIC_TYPE_UNKNOWN    int = iota // 未被定义的指标量
	METRIC_TYPE_COUNTER               // 计数，例如字节数、请求数
	METRIC_TYPE_GAUGE                 // 油标，例如活跃连接数、平均包长
	METRIC_TYPE_DELAY                 // 时延，例如各类时延
	METRIC_TYPE_PERCENTAGE            // 百分比，例如异常比例、重传比例
)

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
}
