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

		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Instant {
			resetQueryInterval(query, 1, 0)
			*query = append(*query, fmt.Sprintf("%s(%s)", "Min", metric))
		} else if queryType == model.Range {
			interval := getRangeInterval(req, "min_over_time")

			resetQueryInterval(query, interval/1e3, getRangeOffset(req, interval)/1e3)
			*query = append(*query, fmt.Sprintf("Percentile(%s, 0)", metric))
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
			// stddev is special calculation, it calculs all points in specific time range
			if len(*query) > 0 {
				(*query)[0] = fmt.Sprintf("toUnixTimestamp(time) AS %s", PROMETHEUS_TIME_COLUMNS)
			} else {
				*query = append(*query, fmt.Sprintf("toUnixTimestamp(time) AS %s", PROMETHEUS_TIME_COLUMNS))
			}
			*query = append(*query, fmt.Sprintf("%s(%s)", "Last", metric))
		}
	},
	"sum_over_time":     simpleCallMatrixFunc("sum_over_time", "Sum"),
	"present_over_time": simpleSelectMatrix("present_over_time", "1"),
	"quantile_over_time": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		if queryType == model.Range {
			interval := getRangeInterval(req, "quantile_over_time")
			resetQueryInterval(query, interval/1e3, getRangeOffset(req, interval)/1e3)
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
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
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
	// ignore counter reset right now
	"idelta":   nil,                     // minus(last, last-1)
	"delta":    nil,                     // minus(last, last-1) without counter reset
	"increase": offloadRate("increase"), // minus(last, first)
	"irate": func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		if queryType == model.Range {
			// NOTICE: for irate, `range` is meaningless, it always calculate the last 2 points
			// e.g.: irate(m[5m]) == irate(m[15m]) == irate(m[1h])
			resetQueryInterval(query, int64(min_interval.Seconds()), getRangeOffset(req, min_interval.Milliseconds())/1e3)
		}

		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		// use default interval to get irate in instant query
		*query = append(*query, fmt.Sprintf("Derivative(%s,%s)", metric, PROMETHEUS_NATIVE_TAG_NAME))
	},
	"rate": offloadRate("rate"), // minus(last, first) / time
}

func getRangeInterval(req model.QueryRequest, f string) int64 {
	step := req.GetStep()
	timeRange := req.GetRange(f) // unit:ms
	subStep := req.GetSubStep(f)
	if step > 0 {
		interval := int64(math.Min(float64(step), float64(timeRange)))
		if subStep > 0 && interval > subStep {
			return subStep
		}
		return interval
	} else {
		return timeRange
	}
}

func getRangeOffset(req model.QueryRequest, interval int64) int64 {
	offset := req.GetStart()%interval + min_interval.Milliseconds()
	return offset
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
			// use min(step, range) as interval
			// if range < step, it will downsampling data
			// if step < range, aggregate to step, then calculate range in engine
			interval := getRangeInterval(req, oriFunc)
			resetQueryInterval(query, interval/1e3, getRangeOffset(req, interval)/1e3)
		}

		*query = append(*query, fmt.Sprintf("%s(%s)", aftFunc, metric))
	}
}

func simpleSelectMatrix(oriFunc string, q string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		if queryType == model.Range {
			interval := getRangeInterval(req, oriFunc)
			resetQueryInterval(query, interval/1e3, getRangeOffset(req, interval)/1e3)
		}
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, q)
	}
}

func offloadRate(fun string) QueryFunc {
	return func(metric string, query, order, group *[]string, req model.QueryRequest, queryType model.QueryType, handleLabelsMatch func(string) string) {
		// for rate/increase, interval is only use for sampling
		// when step/range > scrape_interval, it will downsampling in query
		interval := getRangeInterval(req, fun)
		resetQueryInterval(query, interval/1e3, (getRangeOffset(req, interval)-min_interval.Milliseconds())/1e3)

		*group = append(*group, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		*query = append(*query, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))

		// rate/increase could not implement by Derivative, use other way to offload it

		/*
		 NOTE:
		 what this query trying to get: we should get first & last value and time in each time window
		 why not first(): first() func not supprted
		 why not last(): we build 2-levels sqls, in the inner-level sql it did not order by time asc, so last() cannot get the value of last time, it's random
		 SO:
		 assume metrics are `COUNTER` (only COUNTER with `rate`/`increase` is meaningful)
		 we use MIN/MAX instead of first/last
		 why not min(): min() will do `fill 0` in the time window, so we use Percentile(0) instead of it
		 why not max(time): MAX(time) is not supported
		*/
		*query = append(*query, fmt.Sprintf("Percentile(toUnixTimestamp(time),1) as %s", PROMETHEUS_WINDOW_LAST_TIME))  // last time
		*query = append(*query, fmt.Sprintf("Percentile(toUnixTimestamp(time),0) as %s", PROMETHEUS_WINDOW_FIRST_TIME)) // first time

		*query = append(*query, fmt.Sprintf("Percentile(%s, 0) as %s", metric, PROMETHEUS_WINDOW_FIRST_VALUE)) // first
		*query = append(*query, fmt.Sprintf("Max(%s)", metric))
	}
}
