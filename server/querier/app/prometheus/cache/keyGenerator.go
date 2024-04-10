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
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/prometheus/prometheus/model/labels"
)

type WeakKeyGenerator struct {
}

// weak consistency for match QueryHint & Prometheus Hint
func (w *WeakKeyGenerator) GenerateRequestKey(q model.QueryRequest) string {
	// prometheus hint only have 1 funcs outside of <VectorSelector>
	// so we should only use 1 func for cache key
	var vectorWrapper string
	if len(q.GetFunc()) > 0 {
		vectorWrapper = q.GetFunc()[0]
	}
	return fmt.Sprintf(
		"df:%s:%s:%d:%s:%s:%s:%s",
		q.GetOrgID(),
		q.GetMetric(),
		q.GetStep(),
		generateMatcherKey(q.GetLabels(), ":"),
		vectorWrapper,
		strings.Join(q.GetGrouping(vectorWrapper), ":"),
		strconv.Itoa(int(q.GetRange(vectorWrapper))),
	)
}

type CacheKeyGenerator struct {
}

// generate key without query time (start/end) for cache query
func (k *CacheKeyGenerator) GenerateCacheKey(req *model.DeepFlowPromRequest) string {
	return fmt.Sprintf(
		"df:%s:%s:%d:%d:%d:%s",
		req.OrgID,
		req.Query,
		req.Step,
		req.Start%int64(req.Step.Seconds()), // real interval for data
		req.Slimit,
		strings.Join(req.Matchers, ":"),
	)
}

type HardKeyGenerator struct {
}

// hard consistency for QueryHint match cache data
func (h *HardKeyGenerator) GenerateRequestKey(q model.QueryRequest) string {
	funcs := q.GetFunc()
	return fmt.Sprintf(
		"df:%s:%s:%d:%d:%d:%s:%s:%s:%s:%s",
		q.GetOrgID(),
		q.GetMetric(),
		q.GetStart(),
		q.GetEnd(),
		q.GetStep(),
		generateMatcherKey(q.GetLabels(), ":"),
		strings.Join(funcs, ":"),
		strings.Join(getFuncCallArgs(funcs, func(s string) string {
			return strings.Join(q.GetGrouping(s), ":")
		}), ":"),
		strings.Join(getFuncCallArgs(funcs, func(s string) string {
			return strconv.Itoa(int(q.GetRange(s)))
		}), ":"),
		strings.Join(getFuncCallArgs(funcs, func(s string) string {
			return strconv.Itoa(int(q.GetFuncParam(s)))
		}), ":"),
	)
}

func generateMatcherKey(matchers []*labels.Matcher, splitter string) string {
	m := make([]string, 0, len(matchers))
	f := &strings.Builder{}
	for i := 0; i < len(matchers); i++ {
		f.WriteString(matchers[i].Name)
		f.WriteString(matchers[i].Type.String())
		f.WriteString(matchers[i].Value)
		m = append(m, f.String())
		f.Reset()
	}
	return strings.Join(m, splitter)
}

func getFuncCallArgs(funcs []string, callback func(string) string) []string {
	g := make([]string, 0, len(funcs))
	for _, v := range funcs {
		g = append(g, callback(v))
	}
	return g
}
