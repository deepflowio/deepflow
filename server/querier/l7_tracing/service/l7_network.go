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
	"math"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
)

type L7Network struct {
	L7NetworkMeta *model.L7NetworkMeta
}

func (n L7Network) SetRelate(flows []*model.L7TracingSpan, relatedMap map[string][]string) {
	for _, flow := range flows {
		if flow.OriginID == n.L7NetworkMeta.ID {
			continue
		}
		if flow.Type != common.L7_FLOW_TYPE_RESPONSE && n.L7NetworkMeta.Type != common.L7_FLOW_TYPE_RESPONSE && flow.SpanID != "" {
			if flow.SpanID != n.L7NetworkMeta.SpanID {
				continue
			}
		}
		if n.L7NetworkMeta.Type != common.L7_FLOW_TYPE_RESPONSE && n.L7NetworkMeta.ReqTcpSeq > 0 {
			if math.Abs(float64(n.L7NetworkMeta.StartTimeUs-flow.StartTimeUs)) <= float64(n.L7NetworkMeta.NetworkDelayUs) {
				if n.L7NetworkMeta.ReqTcpSeq == flow.ReqTcpSeq {
					relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-network", n.L7NetworkMeta.ID))
					continue
				}
			}
		}
		if n.L7NetworkMeta.Type != common.L7_FLOW_TYPE_REQUEST && n.L7NetworkMeta.RespTcpSeq > 0 {
			if math.Abs(float64(n.L7NetworkMeta.EndTimeUs-flow.EndTimeUs)) <= float64(n.L7NetworkMeta.NetworkDelayUs) {
				if n.L7NetworkMeta.RespTcpSeq == flow.RespTcpSeq {
					relatedMap[flow.OriginID] = append(relatedMap[flow.OriginID], fmt.Sprintf("%s-network", n.L7NetworkMeta.ID))
					continue
				}
			}
		}
	}
}

func (n L7Network) ToSqlFilter() string {
	// 返回空时需要忽略此条件
	// 由于会话可能没有合并，有一侧的seq可以是零（数据不会存在两侧同时为0的情况）
	// 考虑到网络传输时延，时间需要增加一个delay
	sqlFilters := []string{}
	if n.L7NetworkMeta.Type == common.L7_FLOW_TYPE_SESSION && n.L7NetworkMeta.ReqTcpSeq > 0 && n.L7NetworkMeta.RespTcpSeq > 0 {
		sqlFilters = append(sqlFilters, fmt.Sprintf("((req_tcp_seq=%d AND resp_tcp_seq=%d) OR (req_tcp_seq=%d AND type=0) OR (type=1 AND resp_tcp_seq=%d))", n.L7NetworkMeta.ReqTcpSeq, n.L7NetworkMeta.RespTcpSeq, n.L7NetworkMeta.ReqTcpSeq, n.L7NetworkMeta.RespTcpSeq))
	} else if n.L7NetworkMeta.Type == common.L7_FLOW_TYPE_REQUEST && n.L7NetworkMeta.ReqTcpSeq > 0 {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(req_tcp_seq=%d)", n.L7NetworkMeta.ReqTcpSeq))
	} else if n.L7NetworkMeta.Type == common.L7_FLOW_TYPE_RESPONSE && n.L7NetworkMeta.RespTcpSeq > 0 {
		sqlFilters = append(sqlFilters, fmt.Sprintf("(resp_tcp_seq=%d)", n.L7NetworkMeta.RespTcpSeq))
	}
	if len(sqlFilters) == 0 {
		return "1!=1"
	}
	sqlFilterStr := fmt.Sprintf("(%s)", strings.Join(sqlFilters, " OR "))
	if n.L7NetworkMeta.Type != common.L7_FLOW_TYPE_RESPONSE {
		if n.L7NetworkMeta.SpanID != "" {
			tailorSql := fmt.Sprintf("(span_id='%s' OR type=1 OR span_id='')", n.L7NetworkMeta.SpanID)
			sqlFilterStr = fmt.Sprintf("(%s AND %s)", sqlFilterStr, tailorSql)
		}
	}
	return sqlFilterStr
}
