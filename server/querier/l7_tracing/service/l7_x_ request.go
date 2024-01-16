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

type L7XRequest struct {
	L7XRequestMeta *model.L7XRequestMeta
}

func (s L7XRequest) SetRelate(flows []*model.L7TracingSpan, relatedMap map[string][]string) {
	for _, flow := range flows {
		if flow.OriginID == s.L7XRequestMeta.ID {
			continue
		}
		if s.L7XRequestMeta.XRequestID0 != "" {
			if s.L7XRequestMeta.XRequestID0 == flow.XRequestID1 {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-xrequestid", s.L7XRequestMeta.ID))
				continue
			}
		}
		if s.L7XRequestMeta.XRequestID1 != "" {
			if s.L7XRequestMeta.XRequestID1 == flow.XRequestID0 {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-xrequestid", s.L7XRequestMeta.ID))
				continue
			}
		}
	}
}

func (s L7XRequest) ToSqlFilter() string {
	// 返回空时需要忽略此条件
	sqlFilters := []string{}
	if s.L7XRequestMeta.XRequestID0 != "" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("x_request_id_1='%s'", s.L7XRequestMeta.XRequestID0))
	}
	if s.L7XRequestMeta.XRequestID1 != "" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("x_request_id_0='%s'", s.L7XRequestMeta.XRequestID1))
	}
	if len(sqlFilters) == 0 {
		return "1!=1"
	}
	sqlFilterStr := fmt.Sprintf("(%s)", strings.Join(sqlFilters, " OR "))
	return sqlFilterStr
}
