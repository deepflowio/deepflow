/*
 * Copyright (c) 2023 Yunshan Networks
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
	"strings"

	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
)

type L7App struct {
	L7AppMeta *model.L7AppMeta
}

func (s L7App) SetRelate(flows []*model.L7TracingSpan, relatedMap map[string][]string) {
	for _, flow := range flows {
		if flow.OriginID == s.L7AppMeta.ID {
			continue
		}
		if s.L7AppMeta.SpanID != "" {
			if s.L7AppMeta.SpanID == flow.SpanID || s.L7AppMeta.SpanID == flow.ParentSpanID {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-app", s.L7AppMeta.ID))
				continue
			}
		}
		if s.L7AppMeta.ParentSpanID != "" {
			if s.L7AppMeta.ParentSpanID == flow.SpanID || s.L7AppMeta.ParentSpanID == flow.ParentSpanID {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-app", s.L7AppMeta.ID))
				continue
			}
		}
	}
}

func (s L7App) ToSqlFilter() string {
	// 返回空时需要忽略此条件
	sqlFilters := []string{}
	if s.L7AppMeta.SpanID != "" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(parent_span_id='%s' OR span_id='%s')", s.L7AppMeta.SpanID))
	}
	if s.L7AppMeta.ParentSpanID != "" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(span_id='%s' OR parent_span_id='%s')", s.L7AppMeta.ParentSpanID))
	}
	if len(sqlFilters) == 0 {
		return "1!=1"
	}
	sqlFilterStr := fmt.Sprintf("(%s)", strings.Join(sqlFilters, " OR "))
	return sqlFilterStr
}
