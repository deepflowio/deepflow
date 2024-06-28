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
package common

import (
	"sort"

	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	"golang.org/x/exp/slices"
)

type SortByStartTimeUs []*model.L7TracingSpan

func (s SortByStartTimeUs) Len() int {
	return len(s)
}

func (s SortByStartTimeUs) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortByStartTimeUs) Less(i, j int) bool {
	return s[i].StartTimeUs < s[j].StartTimeUs
}

type SortByType []*model.L7TracingSpan

func (s SortByType) Len() int {
	return len(s)
}

func (s SortByType) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortByType) Less(i, j int) bool {
	return s[i].Type > s[j].Type
}

type SortByTapSide []*model.L7TracingSpan

func (s SortByTapSide) Len() int {
	return len(s)
}

func (s SortByTapSide) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortByTapSide) Less(i, j int) bool {
	return TAP_SIDE_RANKS[s[i].TapSide] < TAP_SIDE_RANKS[s[j].TapSide]
}

func SetParent(flow, parentFlow *model.L7TracingSpan, info string) {
	flow.ParentID = parentFlow.UID
	if flow.Duration >= flow.EndTimeUs-flow.StartTimeUs {
		parentFlow.Duration -= flow.EndTimeUs - flow.StartTimeUs
	} else {
		parentFlow.Duration = 0
	}
	parentFlow.Childs = append(parentFlow.Childs, flow.UID)
	flow.SetParentInfo = info
}

func NetworkFlowSort(flows []*model.L7TracingSpan) []*model.L7TracingSpan {
	/*
	   对网络span进行排序，排序规则：
	   1. 按照TAP_SIDE_RANKS进行排序
	   2. 对Local和rest就近（比较采集器）排到其他位置附近（按时间排）
	*/
	localRestFlows := []*model.L7TracingSpan{}
	sortedFlows := []*model.L7TracingSpan{}
	for _, flow := range flows {
		if slices.Contains[string]([]string{TAP_SIDE_LOCAL, TAP_SIDE_REST}, flow.TapSide) {
			localRestFlows = append(localRestFlows, flow)
		} else {
			sortedFlows = append(sortedFlows, flow)
		}
	}
	sort.Sort(SortByTapSide(sortedFlows))
	if len(sortedFlows) == 0 {
		sortedFlows = append(sortedFlows, localRestFlows...)
	} else {
		for _, localRestFlow := range localRestFlows {
			vtapIndex := -1
			for i, sortedFlow := range sortedFlows {
				if vtapIndex > 0 && sortedFlow.VtapID != localRestFlow.VtapID {
					break
				}
				if sortedFlow.VtapID == localRestFlow.VtapID {
					if sortedFlow.StartTimeUs < localRestFlow.StartTimeUs {
						vtapIndex = i + 1
					} else if vtapIndex == -1 {
						vtapIndex = i
					}
				}
			}
			if vtapIndex >= 0 {
				sortedFlows = append(sortedFlows[:vtapIndex], append([]*model.L7TracingSpan{localRestFlow}, sortedFlows[vtapIndex:]...)...)
			} else {
				for i, sortedFlow := range sortedFlows {
					if localRestFlow.StartTimeUs < sortedFlow.StartTimeUs {
						sortedFlows = append(sortedFlows[:i], append([]*model.L7TracingSpan{localRestFlow}, sortedFlows[i:]...)...)
						break
					}
				}
			}
		}
	}
	return sortedFlows
}

func AppFlowSetService(flows []*model.L7TracingSpan) {
	for _, flow0 := range flows {
		if flow0.ParentID > 0 {
			continue
		}
		for _, flow1 := range flows {
			if flow0.ParentSpanID == flow1.SpanID {
				if flow0.AppService == flow1.AppService {
					if flow0.Service != nil && flow1.Service == nil {
						flow1.Service = flow0.Service
						flow0.Service.AppFlowOfDirectFlows = append(flow0.Service.AppFlowOfDirectFlows, flow0)
					} else if flow0.Service == nil && flow1.Service != nil {
						flow0.Service = flow1.Service
						flow1.Service.AppFlowOfDirectFlows = append(flow1.Service.AppFlowOfDirectFlows, flow0)
					}
				}
				break
			}
		}
	}
}

func AppFlowSort(flows []*model.L7TracingSpan) {
	for _, flow0 := range flows {
		// 1. 若存在parent_span_id，且系统span的span_id等于parent_span_id,则将该应用span的parent设置为该系统span
		if flow0.ParentSyscallFlow != nil {
			SetParent(flow0, flow0.ParentSyscallFlow, "app_flow mounted on syscall due to parent_span_id")
			continue
		}
		for _, flow1 := range flows {
			if flow0.ParentSpanID == flow1.SpanID {
				// 2. 若存在parent_span_id，且span_id等于该parent_span_id的flow存在span_id相同的网络span，则将该应用span的parent设置为该网络span
				if flow1.NetworkFlow != nil {
					SetParent(flow0, flow1.NetworkFlow.Flows[len(flow1.NetworkFlow.Flows)-1], "app_flow mounted due to parent_network")
				} else {
					// 3. 若存在parent_span_id, 将该应用span的parent设置为span_id等于该parent_span_id的flow
					SetParent(flow0, flow1, "app_flow mounted due to parent_span_id")
				}
			}
		}

		if flow0.ParentID > 0 {
			continue
		}
		if flow0.Service != nil {
			// 4. 若有所属service，将该应用span的parent设置为该service的s-p的flow
			if flow0.Service.DirectFlows[0].TapSide == TAP_SIDE_SERVER_PROCESS {
				SetParent(flow0, flow0.Service.DirectFlows[0], "app_flow mouted on s-p in service")
				continue
			}
		}
	}
}

func GetParentFlow(parentFlow *model.L7TracingSpan, flows []*model.L7TracingSpan) *model.L7TracingSpan {
	isGet := false
	for _, flow := range flows {
		if flow.UID == parentFlow.UID {
			continue
		}
		if flow.XRequestID0 == parentFlow.XRequestID1 {
			isGet = true
			return GetParentFlow(flow, flows)
		}
	}
	if !isGet {
		return parentFlow
	}
	return parentFlow
}

func SortByXRequestID(flows []*model.L7TracingSpan) {
	for _, flow0 := range flows {
		if flow0.ParentID == 0 {
			parentFlows := []*model.L7TracingSpan{}
			for _, flow1 := range flows {
				if flow0.UID == flow1.UID {
					continue
				}
				if flow0.XRequestID0 == "" || flow1.XRequestID1 == "" {
					continue
				}
				if flow1.XRequestID1 == flow0.XRequestID0 {
					parentFlows = append(parentFlows, flow1)
				}
			}
			// 如果span有多个父span，选父span的叶子span作为parent
			if len(parentFlows) > 0 {
				parentFlow := GetParentFlow(parentFlows[0], parentFlows)
				SetParent(flow0, parentFlow, "trace mounted due to x_request_id")
			}
		}
	}
}
