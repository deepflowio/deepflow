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
	"sort"

	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	"golang.org/x/exp/slices"
)

type Service struct {
	TraceService *model.TraceService
}

type ServiceKey struct {
	VtapID    int
	ProcessID int
	Index     int
}

func (s Service) ParentSet() {
	sort.Sort(common.SortByStartTimeUs(s.TraceService.AppFlowOfDirectFlows))

	// 有s-p
	if len(s.TraceService.DirectFlows) > 1 && s.TraceService.DirectFlows[0].TapSide == common.TAP_SIDE_SERVER_PROCESS {
		for _, directFlow := range s.TraceService.DirectFlows[1:] {
			if directFlow.ParentID == 0 {
				if directFlow.ParentAppFlow != nil {
					// 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
					common.SetParent(directFlow, directFlow.ParentAppFlow, "c-p mounted on parent_app_flow")
				} else {
					// 2. 所属service中存在应用span，将该系统span的arent设置为service中最后一条应用span
					if len(s.TraceService.AppFlowOfDirectFlows) > 0 {
						common.SetParent(directFlow, s.TraceService.AppFlowOfDirectFlows[len(s.TraceService.AppFlowOfDirectFlows)-1], "c-p mounted on latest app_flow")
					} else {
						// 3. 存在syscalltraceid相同且tap_side=s-p的系统span，该系统span的parent设置为该flow(syscalltraceid相同且tap_side=s-p)
						common.SetParent(directFlow, s.TraceService.DirectFlows[0], "c-p mounted on s-p")
					}
				}
			}
		}
	} else {
		// 只有c-p
		for _, directFlow := range s.TraceService.DirectFlows {
			if directFlow.ParentID == 0 {
				// 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
				if directFlow.ParentAppFlow != nil {
					common.SetParent(directFlow, directFlow.ParentAppFlow, "c-p mounted on own app_flow")
				}
			}
		}
	}
}

// 检查该flow是否与service有关联关系，s-p的时间范围需要覆盖c-p，否则拆分为两个service
func (s Service) CheckClientProcessFlow(flow *model.L7TracingSpan) bool {
	if s.TraceService.ProcessID != flow.ProcessID0 || s.TraceService.VtapID != flow.VtapID {
		return false
	}
	if s.TraceService.StartTimeUs > flow.StartTimeUs || s.TraceService.EndTimeUs < flow.EndTimeUs {
		return false
	}
	return true
}

// directFlow是指该服务直接接收到的，或直接发出的flow
func (s Service) AddDirectFlow(flow *model.L7TracingSpan) {
	if flow.TapSide == common.TAP_SIDE_SERVER_PROCESS {
		s.TraceService.StartTimeUs = flow.StartTimeUs
		s.TraceService.EndTimeUs = flow.EndTimeUs
	}
	if s.TraceService.SubnetID != 0 {
		flow.SubnetID = s.TraceService.SubnetID
	} else {
		if flow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
			s.TraceService.SubnetID = flow.SubnetID0
		} else {
			s.TraceService.SubnetID = flow.SubnetID1
		}
		flow.SubnetID = s.TraceService.SubnetID
	}
	if s.TraceService.Subnet != "" {
		flow.Subnet = s.TraceService.Subnet
	} else {
		if flow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
			s.TraceService.Subnet = flow.Subnet0
		} else {
			s.TraceService.Subnet = flow.Subnet1
		}
		flow.Subnet = s.TraceService.Subnet
	}
	if s.TraceService.IP != "" {
		flow.IP = s.TraceService.IP
	} else {
		if flow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
			s.TraceService.IP = flow.IP0
		} else {
			s.TraceService.IP = flow.IP1
		}
		flow.IP = s.TraceService.IP
	}
	if s.TraceService.ProcessKname != "" {
		flow.ProcessKname1 = s.TraceService.ProcessKname
	} else {
		if flow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
			s.TraceService.ProcessKname = flow.ProcessKname0
		} else {
			s.TraceService.ProcessKname = flow.ProcessKname1
		}
		flow.ProcessKname = s.TraceService.ProcessKname
	}
	if s.TraceService.AutoServiceType == 0 || s.TraceService.AutoServiceType == 255 {
		if flow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
			s.TraceService.AutoServiceType = flow.AutoServiceType0
			s.TraceService.AutoServiceID = flow.AutoServiceID0
			s.TraceService.AutoService = flow.AutoService0
		} else {
			s.TraceService.AutoServiceType = flow.AutoServiceType1
			s.TraceService.AutoServiceID = flow.AutoServiceID1
			s.TraceService.AutoService = flow.AutoService1
		}
		flow.AutoServiceType = s.TraceService.AutoServiceType
		flow.AutoServiceID = s.TraceService.AutoServiceID
		flow.AutoService = s.TraceService.AutoService
	} else {
		flow.AutoServiceType = s.TraceService.AutoServiceType
		flow.AutoServiceID = s.TraceService.AutoServiceID
		flow.AutoService = s.TraceService.AutoService
	}
	s.TraceService.DirectFlows = append(s.TraceService.DirectFlows, flow)
}

func (s Service) AttachAppFlow(flow *model.L7TracingSpan) bool {
	if !slices.Contains[string]([]string{common.TAP_SIDE_CLIENT_APP, common.TAP_SIDE_SERVER_APP, common.TAP_SIDE_APP}, flow.TapSide) {
		return false
	}
	for _, directFlow := range s.TraceService.DirectFlows {
		// span_id相同 x-p的parent一定是x-app
		if directFlow.SpanID != "" && directFlow.SpanID == flow.SpanID {
			directFlow.ParentAppFlow = flow
			// 只有c-p和x-app的span_id相同时，属于同一个service
			if directFlow.TapSide == common.TAP_SIDE_CLIENT_PROCESS {
				flow.Service = s.TraceService
				s.TraceService.AppFlowOfDirectFlows = append(s.TraceService.AppFlowOfDirectFlows, flow)
				return true
			}
		}
	}
	// x-app的parent是s-p时，一定属于同一个service
	if len(s.TraceService.DirectFlows) > 0 && flow.ParentSpanID != "" && s.TraceService.DirectFlows[0].SpanID != "" && flow.ParentSpanID == s.TraceService.DirectFlows[0].SpanID && s.TraceService.DirectFlows[0].TapSide == common.TAP_SIDE_SERVER_PROCESS {
		// x-app的parent是c-p时，一定不属于同一个service
		if len(s.TraceService.DirectFlows) > 1 {
			// x-app的parent是c-p时，一定不属于同一个service
			for _, clientProcessFlow := range s.TraceService.DirectFlows[1:] {
				if flow.ParentSpanID == clientProcessFlow.SpanID {
					flow.ParentSyscallFlow = clientProcessFlow
					return false
				}
			}
			flow.ParentSyscallFlow = s.TraceService.DirectFlows[0]
			flow.Service = s.TraceService
			s.TraceService.AppFlowOfDirectFlows = append(s.TraceService.AppFlowOfDirectFlows, flow)
			return true
		}
	}
	return false
}
