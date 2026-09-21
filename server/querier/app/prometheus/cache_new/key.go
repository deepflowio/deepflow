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

package cachenew

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/op/go-logging"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

var log = logging.MustGetLogger("prometheus.cache_new")

// ---------------------------------------------------------------------------
// Time utilities
// ---------------------------------------------------------------------------

// timeAlign snaps a start time (in seconds) down to the nearest minute
// so that queries starting at slightly different offsets share the same key.
// e.g. query [13s, 117s] → cached as [0s, 120s].
func timeAlign(startSeconds int64) int64 {
	return startSeconds - startSeconds%60
}

// GetPromRequestQueryTime extracts the canonical [start, end] in seconds from a prompb.Query.
func GetPromRequestQueryTime(q *prompb.Query) (int64, int64) {
	endTime := q.Hints.EndMs / 1000
	if q.Hints.EndMs%1000 > 0 {
		endTime++
	}
	return q.Hints.StartMs / 1000, endTime
}

// promRequestToCacheKey builds a stable cache key from a prompb.Query,
// org filter string, and extra filters. The key excludes the time range
// so the same metric query at different windows maps to the same cache slot.
func promRequestToCacheKey(q *prompb.Query, orgFilter, extraFilters string) string {
	var b strings.Builder
	if len(orgFilter) > 0 {
		b.WriteString(orgFilter)
		b.WriteByte('-')
	}
	if len(extraFilters) > 0 {
		b.WriteString(extraFilters)
		b.WriteByte('-')
	}
	for _, m := range q.Matchers {
		b.WriteString(m.GetName())
		b.WriteString(m.Type.String())
		b.WriteString(m.GetValue())
		b.WriteByte('-')
	}
	if common.IsValueInSliceString(q.Hints.Func, model.RelabelFunctions) {
		b.WriteString("RELABEL_FUNC_CACHE")
	}
	return b.String()
}

// GetMetricFromLabelMatcher returns the __name__ value from a label matcher list.
func GetMetricFromLabelMatcher(matchers *[]*prompb.LabelMatcher) string {
	for _, m := range *matchers {
		if m.Name == "__name__" {
			return m.Value
		}
	}
	return ""
}

// labelsEqual reports whether two labels.Labels are identical.
func labelsEqual(a, b labels.Labels) bool {
	return labels.Equal(a, b)
}

// ---------------------------------------------------------------------------
// Key generators (unchanged from original; retained for callers that use them)
// ---------------------------------------------------------------------------

// WeakKeyGenerator generates cache keys with weak time consistency.
// It uses only the first function hint, which matches the single-function
// constraint of Prometheus QueryHints outside of VectorSelector.
type WeakKeyGenerator struct{}

func (w *WeakKeyGenerator) GenerateRequestKey(q model.QueryRequest) string {
	var vectorWrapper string
	if fns := q.GetFunc(); len(fns) > 0 {
		vectorWrapper = fns[0]
	}
	return fmt.Sprintf(
		"df:%s:%d:%s:%s:%s:%s",
		q.GetMetric(),
		q.GetStep(),
		generateMatcherKey(q.GetLabels(), ":"),
		vectorWrapper,
		strings.Join(q.GetGrouping(vectorWrapper), ":"),
		strconv.Itoa(int(q.GetRange(vectorWrapper))),
	)
}

// CacheKeyGenerator generates keys without the query time range,
// so the same query at different windows maps to a single cache slot.
type CacheKeyGenerator struct{}

func (k *CacheKeyGenerator) GenerateCacheKey(req *model.DeepFlowPromRequest) string {
	return fmt.Sprintf(
		"df:%s:%s:%s:%s:%d:%d:%d:%s",
		req.OrgID,
		strings.Join(req.BlockTeamID, "-"),
		req.ExtraFilters,
		req.Query,
		req.Step,
		req.Start%int64(req.Step.Seconds()),
		req.Slimit,
		strings.Join(req.Matchers, ":"),
	)
}

// HardKeyGenerator generates keys that include the full time range,
// providing strong consistency between the QueryHint and the cached data.
type HardKeyGenerator struct{}

func (h *HardKeyGenerator) GenerateRequestKey(q model.QueryRequest) string {
	funcs := q.GetFunc()
	return fmt.Sprintf(
		"df:%s:%d:%d:%d:%s:%s:%s:%s:%s",
		q.GetMetric(),
		q.GetStart(),
		q.GetEnd(),
		q.GetStep(),
		generateMatcherKey(q.GetLabels(), ":"),
		strings.Join(funcs, ":"),
		strings.Join(mapFuncs(funcs, func(s string) string { return strings.Join(q.GetGrouping(s), ":") }), ":"),
		strings.Join(mapFuncs(funcs, func(s string) string { return strconv.Itoa(int(q.GetRange(s))) }), ":"),
		strings.Join(mapFuncs(funcs, func(s string) string { return strconv.Itoa(int(q.GetFuncParam(s))) }), ":"),
	)
}

func generateMatcherKey(matchers []*labels.Matcher, splitter string) string {
	parts := make([]string, 0, len(matchers))
	var b strings.Builder
	for _, m := range matchers {
		b.WriteString(m.Name)
		b.WriteString(m.Type.String())
		b.WriteString(m.Value)
		parts = append(parts, b.String())
		b.Reset()
	}
	return strings.Join(parts, splitter)
}

// mapFuncs applies callback to each element of funcs and returns the results.
func mapFuncs(funcs []string, callback func(string) string) []string {
	out := make([]string, len(funcs))
	for i, f := range funcs {
		out[i] = callback(f)
	}
	return out
}
