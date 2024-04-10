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

package cache

import (
	"strings"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/op/go-logging"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

var log = logging.MustGetLogger("prometheus.cache")

type CacheHit int

const (
	CacheMiss CacheHit = iota
	CacheHitPart
	CacheHitFull
	CacheKeyNotFound
	CacheKeyFoundNil
)

// start time & end time align to 0 second
// e.g.: query 13s-117s, cache 0s-120s
func timeAlign(startSeconds int64) int64 {
	return startSeconds - startSeconds%60
}

func GetPromRequestQueryTime(q *prompb.Query) (int64, int64) {
	// remind that we storage seconds for prometheus samples
	// if the sample storage changes to milliseconds, it shoudld remove `/1000` here
	endTime := q.Hints.EndMs / 1000
	// if endTime is not multiple of 1000, add 1 for endTime for data points outside end
	if q.Hints.EndMs%1000 > 0 {
		endTime += 1
	}
	return q.Hints.StartMs / 1000, endTime
}

func promRequestToCacheKey(q *prompb.Query, orgID string) string {
	matcher := &strings.Builder{}
	matcher.WriteString(orgID + "-")
	for i := 0; i < len(q.Matchers); i++ {
		matcher.WriteString(q.Matchers[i].GetName() + q.Matchers[i].Type.String() + q.Matchers[i].GetValue())
		matcher.WriteByte('-')
	}
	if common.IsValueInSliceString(q.Hints.Func, model.RelabelFunctions) {
		// for all relabel functions, use label_index in query, will append the same cache
		matcher.WriteString("RELABEL_FUNC_CACHE")
	}
	return matcher.String()
}

func GetMetricFromLabelMatcher(matchers *[]*prompb.LabelMatcher) string {
	var metric string
	for i := 0; i < len(*matchers); i++ {
		if (*matchers)[i].Name == "__name__" {
			metric = (*matchers)[i].Value
		}
	}
	return metric
}

func promLabelsEqual(new *labels.Labels, old *labels.Labels) bool {
	if new == nil || old == nil || len(*new) != len(*old) {
		return false
	}
	for i := 0; i < len(*old); i++ {
		if (*old)[i].Name != (*new)[i].Name || (*old)[i].Value != (*new)[i].Value {
			return false
		}
	}
	return true
}

func getpbLabelString(labels *[]prompb.Label, key string) string {
	// __cache_labels__string__ mostly append in last index, reverse scan avoid useless loop
	for i := len(*labels) - 1; i >= 0; i-- {
		if (*labels)[i].Name == key {
			return (*labels)[i].Value
		}
	}
	return ""
}
