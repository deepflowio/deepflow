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

package model

import (
	"github.com/prometheus/prometheus/model/labels"
)

type QueryRequest interface {
	// GetStart returns the start timestamp of query, unit: ms
	GetStart() int64

	// GetEnd returns the end timestamp of query, unit: ms
	GetEnd() int64

	// GetStep returns the query step of range-query
	GetStep() int64

	// GetFunc returns the query aggregation functions of query
	GetFunc() []string

	// GetGrouping returns the group labels for query functions of query
	GetGrouping(f string) []string

	// GetBy returns the group way for group labels of query
	GetBy() bool

	// GetQuery returns the whole query promql of query
	GetQuery() string

	// GetMetric returns the metric name of query
	GetMetric() string

	// GetLables returns query labels of query
	GetLabels() []*labels.Matcher

	// GetRange returns the range of query function
	GetRange(f string) int64

	// GetFuncParam returns query params of query function, only for 'topk'/'quantile'/'bottomk'
	GetFuncParam(f string) float64
}

/*
difference between those query type:
- series query: get `series` only, it won't get any time series samples; don't use cache
  - params: start, end, matchers
- instant query: get instant value
  - params: start, end, query(metric, matchers, func, range)
  - specially: subQuery with step, but it should calculated in memory, not databases
- range query: get time series samples for multiple values
  - params: start, end, step, query(metric, matchers, func, range)
*/

type QueryType uint8

const (
	// Series Query
	Series QueryType = iota
	// Instant Query
	Instant
	// Range Query
	Range
)
