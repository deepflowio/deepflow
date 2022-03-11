package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
)

type Metric struct {
	// 以下字段对外
	DBField     string   // 数据库字段
	DisplayName string   // 描述
	Unit        string   // 单位
	Functions   []string // 支持的算子

	// 以下字段对内
	InnerMetrics   []view.Function // 内层结构，用于需要拆分为双层算子时内层使用的算子结构
	UnlayFunctions []string        // 支持不拆层的算子
	Is0Meaningful  bool            // 0值是否有意义，有意义则会将null作为0处理，无意义则将0作为null处理
}

func GetMetrc(field string) *Metric {
	allMetrics := GetAllMetrcs()
	if metric, ok := allMetrics[field]; ok {
		return metric
	}
	return nil
}

func GetAllMetrcs() map[string]*Metric {
	return map[string]*Metric{
		"byte": &Metric{
			DBField: "byte", DisplayName: "字节", Unit: "字节",
			Functions: []string{view.FUNCTION_SUM, view.FUNCTION_MAX, view.FUNCTION_MIN},
			InnerMetrics: []view.Function{
				&view.DefaultFunction{
					Name:   view.FUNCTION_SUM,
					Fields: []view.Node{&view.Field{Value: "byte"}}},
			},
			UnlayFunctions: []string{view.FUNCTION_SUM},
			Is0Meaningful:  view.METRIC_IS_0_MEANINGFUL_TRUE,
		},
		"bit": &Metric{
			DBField: "byte*8", DisplayName: "比特", Unit: "比特",
			Functions: []string{view.FUNCTION_SUM, view.FUNCTION_MAX, view.FUNCTION_MIN},
			InnerMetrics: []view.Function{
				&view.DefaultFunction{
					Name:   view.FUNCTION_SUM,
					Fields: []view.Node{&view.Field{Value: "byte*8"}}},
			},
			UnlayFunctions: []string{view.FUNCTION_SUM},
			Is0Meaningful:  view.METRIC_IS_0_MEANINGFUL_TRUE,
		},
		"rtt_max": &Metric{
			DBField: "rtt_max", DisplayName: "最大TCP建连时延", Unit: "微秒",
			Functions:      []string{view.FUNCTION_SUM, view.FUNCTION_MAX, view.FUNCTION_MIN},
			UnlayFunctions: []string{view.FUNCTION_SUM, view.FUNCTION_MAX, view.FUNCTION_MIN},
			Is0Meaningful:  view.METRIC_IS_0_MEANINGFUL_FALSE,
		},
	}
}
