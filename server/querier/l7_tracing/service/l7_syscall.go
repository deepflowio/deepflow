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

type L7Syscall struct {
	L7SyscallMeta *model.L7SyscallMeta
}

func (s L7Syscall) SetRelate(flows []*model.L7TracingSpan, relatedMap map[string][]string) {
	for _, flow := range flows {
		if flow.OriginID == s.L7SyscallMeta.ID {
			continue
		}
		if flow.VtapID != s.L7SyscallMeta.VtapID {
			continue
		}
		if s.L7SyscallMeta.SyscallTraceIDRequest != "0" {
			if s.L7SyscallMeta.SyscallTraceIDRequest == flow.SyscallTraceIDRequest || s.L7SyscallMeta.SyscallTraceIDRequest == flow.SyscallTraceIDResponse {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-syscall", s.L7SyscallMeta.ID))
				continue
			}
		}
		if s.L7SyscallMeta.SyscallTraceIDResponse != "0" {
			if s.L7SyscallMeta.SyscallTraceIDResponse == flow.SyscallTraceIDRequest || s.L7SyscallMeta.SyscallTraceIDResponse == flow.SyscallTraceIDResponse {
				relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-syscall", s.L7SyscallMeta.ID))
				continue
			}
		}
	}
}

func (s L7Syscall) ToSqlFilter() string {
	// 返回空时需要忽略此条件
	sqlFilters := []string{}
	if s.L7SyscallMeta.SyscallTraceIDRequest != "0" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(syscall_trace_id_request=%s OR syscall_trace_id_response=%s)", s.L7SyscallMeta.SyscallTraceIDRequest))
	}
	if s.L7SyscallMeta.SyscallTraceIDResponse != "0" {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(syscall_trace_id_request=%s OR syscall_trace_id_response=%s)", s.L7SyscallMeta.SyscallTraceIDResponse))
	}
	if len(sqlFilters) == 0 {
		return "1!=1"
	}
	sqlFilterStr := fmt.Sprintf("(vtap_id=%d AND (%s))", s.L7SyscallMeta.VtapID, strings.Join(sqlFilters, " OR "))
	return sqlFilterStr
}
