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

package service

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
)

const (
	_prometheus_tag_key = "FastTrans(tag)"
	min_interval        = 10 * time.Second
)

type offloadEnabledFunc func(string, []string, bool) bool

// validate `func` & `by`, return if the <XSelector> can be offloaded
func offloadEnabled(metric string, funcs []string, by bool) bool {
	// if func() without (tags), can not be offloaded
	// not offloaded DeepFlow Native Metric, because it's already offloaded
	if strings.Contains(metric, "__") || !by || len(funcs) == 0 {
		return false
	}

	// when len(funcs)>2, we don't consider offload
	// the inner function offloaded <VectorSelector> for data reduce is enough, i.e.: sum(rate(x))
	maxIterateLevel := math.Min(float64(len(funcs)), 2)
	for i := 0; i < int(maxIterateLevel); i++ {
		if QueryFuncCall[funcs[i]] == nil {
			return false
		}
	}
	return true
}

type QueryFunc func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string)

// NOTICE: query `value` should be LAST index of `query`, it will append `query` as value outside of QueryFuncCall
var QueryFuncCall = map[string]QueryFunc{
	// Vector
	"avg_over_time":   simpleCallMatrixFunc("avg_over_time", "AAvg"),
	"count_over_time": simpleSelectMatrix("count_over_time", "Count(row)"),
	"last_over_time":  simpleCallMatrixFunc("last_over_time", "Last"),
	"max_over_time":   simpleCallMatrixFunc("max_over_time", "Max"),
	"min_over_time": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		// `Min` in querier will try get min(value, 0) in the query time window
		// when use instant query, toUnixTimestamp will use [5m] time window, it required 5m/10s +1=31 data points in time window, otherwise it will get `0`
		// if(count(`_sum_value`)=31, min(`_sum_value`), 0)
		// so we specific time window=1s here

		resetQueryInterval(query, 1, 0)
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Instant {
			*query = append(*query, fmt.Sprintf("%s(%s)", "Min", metric))
		} else if queryType == model.Range {
			*query = append(*query, fmt.Sprintf("Last(%s)", metric))
		}
	},
	"stddev_over_time": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Instant {
			if len(*query) > 0 {
				(*query)[0] = fmt.Sprintf("%d AS %s", req.GetEnd()/1e3, PROMETHEUS_TIME_COLUMNS)
			} else {
				*query = append(*query, fmt.Sprintf("%d AS %s", req.GetEnd()/1e3, PROMETHEUS_TIME_COLUMNS))
			}
			*query = append(*query, fmt.Sprintf("%s(%s)", "Stddev", metric))
		} else if queryType == model.Range {
			resetQueryInterval(query, 1, 0)
			*query = append(*query, fmt.Sprintf("%s(%s)", "Last", metric))
		}
	},
	"sum_over_time":     simpleCallMatrixFunc("sum_over_time", "Sum"),
	"present_over_time": simpleSelectMatrix("count_over_time", "1"),
	"quantile_over_time": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Range {
			step := req.GetStep()
			timeRange := req.GetRange("quantile_over_time") // unit:ms
			interval := int64(math.Min(float64(step), float64(timeRange)))
			offset := req.GetStart()%interval + min_interval.Milliseconds()

			resetQueryInterval(query, interval/1e3, offset/1e3)
		}

		quantile_param := req.GetFuncParam("quantile_over_time")
		*query = append(*query, fmt.Sprintf("%s(%s, %g)", "Percentile", metric, quantile_param))
	},

	// aggregation operators
	"sum": simpleCallFunc("sum", "Sum"),
	"min": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		resetQueryInterval(query, 1, 0)
		*query = append(*query, fmt.Sprintf("%s as %s", _prometheus_tag_key, PROMETHEUS_LABELS_INDEX))
		*query = append(*query, fmt.Sprintf("%s(%s)", "Min", metric))
		*group = append(*group, PROMETHEUS_LABELS_INDEX)

		for _, tag := range req.GetGrouping("min") {
			*group = append(*group, handleLabelsMatch(tag))
		}
	},
	"max":          simpleCallFunc("max", "Max"),
	"avg":          simpleCallFunc("avg", "AAvg"),
	"stddev":       nil,
	"group":        simpleSelection("group", "1"),
	"count":        simpleSelection("count", "Count(row)"),
	"count_values": simpleCallFunc("count_values", "Last"),

	"topk": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		if len(*group) == 0 {
			*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
			*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		}
		*query = append(*query, fmt.Sprintf("Max(%s)", metric)) // use for max value, then order by value, try best to get topN
		// *order = append(*order, fmt.Sprintf("%s desc", metric))
	},

	"bottomk": nil, // don't use Min(%s), because min will fill zero as default value

	"quantile": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*group = append(*group, PROMETHEUS_LABELS_INDEX)
		*query = append(*query, fmt.Sprintf("%s as %s", _prometheus_tag_key, PROMETHEUS_LABELS_INDEX))
		quantile_param := req.GetFuncParam("quantile")
		*query = append(*query, fmt.Sprintf("Percentile(%s, %g)", metric, quantile_param))
		for _, tag := range req.GetGrouping("quantile") {
			*group = append(*group, handleLabelsMatch(tag))
		}
	},

	// range-vector functions, but needs counter reset
	"idelta":   nil, // minus(last, last-1) maybe: (nonNegativeDerivative * interval?)
	"increase": nil, // minus(last, first) maybe: (nonNegativeDerivative * interval?)
	"delta":    nil, // minus(last, last-1) without counter reset (nonNegativeDerivative)

	"irate": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		if queryType == model.Range {
			// NOTICE: for irate, `range` is meaningless, it always calculate the last 2 points
			// e.g.: irate(m[5m]) == irate(m[15m]) == irate(m[1h])

			// use toUnixTimestamp will change to time(time, 15) as default interval grouping when using Derivative func
			if len(*query) > 0 {
				(*query)[0] = fmt.Sprintf("toUnixTimestamp(time) AS %s", PROMETHEUS_TIME_COLUMNS)
			} else {
				*query = append(*query, fmt.Sprintf("toUnixTimestamp(time) AS %s", PROMETHEUS_TIME_COLUMNS))
			}
		}

		if len(*group) == 0 {
			*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
			*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		}

		// use default interval to get irate in instant query
		*query = append(*query, fmt.Sprintf("Derivative(%s,%s)", metric, PROMETHEUS_NATIVE_TAG_NAME))
	},

	"rate": nil, // not implemented
	// the functions below is PARTLY correct, but is not fully correct
	// like, when we try to get rate(m[5m]), it gets rate(m[5m+(scrape_interval)m]) actually, it's always calculate 1 more point
	// KEEP this for a refer
	// 目前计算 rate 算子不正确，因为 time() 会聚合时间范围[5m]内的数据，再做相邻计算，无法确定准确的聚合时间窗口（因取决于 scrape_interval）
	// 期望：(m.At(5m)-m.At(0))/5m, 实际：(m.At(5m+1m)-m.At(5m))/1m
	// 保留注释以供参考
	// func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
	// 	var interval, offset int64
	// 	if queryType == model.Instant {
	// 		interval = req.GetRange("rate")
	// 		// when timeRange > 1m, use t-1m as rate range
	// 		// otherwise it calculs wrong value
	// 		if interval > 0 {
	// 			offset = req.GetStart() % interval
	// 		}
	// 	} else if queryType == model.Range {
	// 		step := req.GetStep()
	// 		timeRange := req.GetRange("rate") // unit:ms
	// 		// use min(step, range) as interval
	// 		// if range < step, it will downsampling data
	// 		// if step < range, ???
	// 		interval = int64(math.Min(float64(step), float64(timeRange)))
	// 		offset = req.GetStart() % interval
	// 	}

	// 	// set `time` column query
	// 	if len(*query) > 0 {
	// 		(*query)[0] = fmt.Sprintf("time(time, %d, 1,'', %d) AS %s", interval/1e3, offset/1e3, PROMETHEUS_TIME_COLUMNS)
	// 	} else {
	// 		*query = append(*query, fmt.Sprintf("time(time, %d, 1, '', %d) AS %s", interval/1e3, offset/1e3, PROMETHEUS_TIME_COLUMNS))
	// 	}

	// 	if len(*group) == 0 {
	// 		*group = append(*group, _prometheus_tag_key)
	// 		*query = append(*query, _prometheus_tag_key)
	// 	}

	// 	*query = append(*query, fmt.Sprintf("Last(%s)", metric))
	// },
}

func resetQueryInterval(query *[]string, interval, offset int64) {
	timeCol := fmt.Sprintf("time(time, %d) AS %s", interval, PROMETHEUS_TIME_COLUMNS)
	if offset > 0 {
		timeCol = fmt.Sprintf("time(time, %d, 1,'', %d) AS %s", interval, offset, PROMETHEUS_TIME_COLUMNS)
	}
	if len(*query) > 0 {
		(*query)[0] = timeCol
	} else {
		*query = append(*query, timeCol)
	}
}

func simpleSelection(oriFunc string, aftFunc string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*query = append(*query, fmt.Sprintf("%s as %s", _prometheus_tag_key, PROMETHEUS_LABELS_INDEX))
		*query = append(*query, aftFunc)
		*group = append(*group, PROMETHEUS_LABELS_INDEX)
		for _, tag := range req.GetGrouping(oriFunc) {
			*group = append(*group, handleLabelsMatch(tag))
		}
	}
}

func simpleCallFunc(oriFunc string, aftFunc string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*query = append(*query, fmt.Sprintf("%s as %s", _prometheus_tag_key, PROMETHEUS_LABELS_INDEX))
		*query = append(*query, fmt.Sprintf("%s(%s)", aftFunc, metric))
		*group = append(*group, PROMETHEUS_LABELS_INDEX)
		for _, tag := range req.GetGrouping(oriFunc) {
			*group = append(*group, handleLabelsMatch(tag))
		}
	}
}

/*
in matrix selector, we need to + min_interval to avoid duplicated calculation here
i.e.: for points in [01:01, 02:02, 03:03, 04:04, 05:05]
in clickhouse, we aggregated to [01:00, 02:00, 03:00, 04:00, 05:00]
when we use sum_over_time at [05:00], it sum 01-05 points, but 01-04 it expected (05:05>05:00)
so we make + min_interval to bring 05:00 point to the next point
*/
func simpleCallMatrixFunc(oriFunc string, aftFunc string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Range {
			step := req.GetStep()
			timeRange := req.GetRange(oriFunc) // unit:ms
			// use min(step, range) as interval
			// if range < step, it will downsampling data
			// if step < range, aggregate to step, then calculate range in engine
			interval := int64(math.Min(float64(step), float64(timeRange)))
			offset := req.GetStart()%interval + min_interval.Milliseconds()

			resetQueryInterval(query, interval/1e3, offset/1e3)
		}

		*query = append(*query, fmt.Sprintf("%s(%s)", aftFunc, metric))
	}
}

func simpleSelectMatrix(oriFunc string, q string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		if queryType == model.Range {
			step := req.GetStep()
			timeRange := req.GetRange(oriFunc) // unit:ms
			interval := int64(math.Min(float64(step), float64(timeRange)))
			offset := req.GetStart()%interval + min_interval.Milliseconds()

			resetQueryInterval(query, interval/1e3, offset/1e3)
		}
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, q)
	}
}
