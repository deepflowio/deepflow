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
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("l7_tracing")

func Tracing(args model.L7Tracing, cfg *config.QuerierConfig) (result []*model.L7TracingSpan, debug interface{}, err error) {
	return
}

func MergeFlow(flows []*model.L7TracingSpan, mergeFlow *model.L7TracingSpan) (isMerge bool) {
	/*
	   只有一个请求和一个响应能合并，不能合并多个请求或多个响应；
	   按如下策略合并：
	   按start_time递增的顺序从前向后扫描，每发现一个请求，都找一个它后面离他最近的响应。
	   例如：请求1、请求2、响应1、响应2
	   则请求1和响应1配队，请求2和响应2配队
	*/
	if mergeFlow.Type == common.L7_FLOW_TYPE_SESSION && !slices.Contains[string]([]string{common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_CLIENT_PROCESS}, mergeFlow.TapSide) {
		return
	}

	for _, flow := range flows {
		if flow.OriginID == mergeFlow.OriginID {
			continue
		}
		if mergeFlow.VtapID != flow.VtapID || mergeFlow.TapPort != flow.TapPort || mergeFlow.TapPortType != flow.TapPortType || mergeFlow.L7Protocol != flow.L7Protocol || *mergeFlow.RequestID != *flow.RequestID || mergeFlow.TapSide != flow.TapSide {
			continue
		}
		if !slices.Contains[string]([]string{common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_CLIENT_PROCESS}, flow.TapSide) {
			if flow.Type == common.L7_FLOW_TYPE_SESSION {
				continue
			}
			// 每条flow的_id最多只有一来一回两条
			if len(flow.IDs) > 1 || flow.Type == mergeFlow.Type {
				continue
			}
		}

		requestFlow := &model.L7TracingSpan{}
		responseFlow := &model.L7TracingSpan{}
		if flow.Type == common.L7_FLOW_TYPE_REQUEST || mergeFlow.Type == common.L7_FLOW_TYPE_RESPONSE {
			requestFlow = flow
			responseFlow = mergeFlow
		} else if flow.Type == common.L7_FLOW_TYPE_RESPONSE || mergeFlow.Type == common.L7_FLOW_TYPE_REQUEST {
			requestFlow = mergeFlow
			responseFlow = flow
		} else {
			continue
		}
		if flow.Type != mergeFlow.Type && requestFlow.StartTimeUs > responseFlow.EndTimeUs {
			return
		}
		if slices.Contains[string]([]string{common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_CLIENT_PROCESS}, requestFlow.TapSide) {
			// 应用span syscall_cap_seq判断合并
			if requestFlow.SyscallCapSeq0+1 != responseFlow.SyscallCapSeq1 {
				return
			}
		}

		// 合并字段
		flow.IDs = append(flow.IDs, mergeFlow.IDs...)
		flow.AutoInstance0 = mergeFlow.AutoInstance0
		flow.AutoInstance1 = mergeFlow.AutoInstance1
		flow.AutoService0 = mergeFlow.AutoService0
		flow.AutoService1 = mergeFlow.AutoService1

		if mergeFlow.Type != common.L7_FLOW_TYPE_RESPONSE {
			flow.L7Protocol = mergeFlow.L7Protocol
			flow.L7ProtocolStr = mergeFlow.L7ProtocolStr
			flow.Protocol = mergeFlow.Protocol
			flow.Version = mergeFlow.Version
			flow.RequestID = mergeFlow.RequestID
			flow.TraceID = mergeFlow.TraceID
			flow.SpanID = mergeFlow.SpanID
			flow.Endpoint = mergeFlow.Endpoint
		}
		if mergeFlow.Type != common.L7_FLOW_TYPE_REQUEST {
			flow.HttpProxyClient = mergeFlow.HttpProxyClient
		}
		flow.XRequestID0 = mergeFlow.XRequestID0
		flow.XRequestID1 = mergeFlow.XRequestID1

		if mergeFlow.Type == common.L7_FLOW_TYPE_REQUEST {
			if mergeFlow.StartTimeUs < flow.StartTimeUs {
				flow.StartTimeUs = mergeFlow.StartTimeUs
			} else if flow.ReqTcpSeq == 0 {
				flow.ReqTcpSeq = mergeFlow.ReqTcpSeq
			}
			flow.SyscallCapSeq0 = mergeFlow.SyscallCapSeq0
		} else if mergeFlow.Type == common.L7_FLOW_TYPE_RESPONSE {
			if mergeFlow.EndTimeUs > flow.EndTimeUs {
				flow.EndTimeUs = mergeFlow.EndTimeUs
				if flow.RespTcpSeq == 0 {
					flow.RespTcpSeq = mergeFlow.RespTcpSeq
				}
			}
			flow.SyscallCapSeq1 = mergeFlow.SyscallCapSeq1
		} else {
			flow.ReqTcpSeq = mergeFlow.ReqTcpSeq
			flow.RespTcpSeq = mergeFlow.RespTcpSeq
		}

		// request response合并后type改为session
		if mergeFlow.Type+flow.Type == 1 {
			flow.Type = 2
		} else if mergeFlow.Type > flow.Type {
			flow.Type = mergeFlow.Type
		}
		return true
	}
	return
}

func SortAllFlows(flows []*model.L7TracingSpan, NetworkDelayUs, NtpDelayUs int) ([]Service, []*model.L7TracingSpan, []Network) {
	/*
			对应用流日志排序，用于绘制火焰图。

		    1. 根据系统调用追踪信息追踪：
		          1 -> +-----+
		               |     | -> 2
		               |     | <- 2
		               | svc |
		               |     | -> 3
		               |     ! <- 3
		          1 <- +-----+
		       上图中的服务进程svc在接受请求1以后，向下游继续请求了2、3，他们之间的关系是：
		          syscall_trace_id_request_1  = syscall_trace_id_request_2
		          syscall_trace_id_response_2 = syscall_trace_id_request_3
		          syscall_trace_id_response_3 = syscall_trace_id_response_1
		       上述规律可用于追踪系统调用追踪信息发现的流日志。

		    2. 根据主动注入的追踪信息追踪：
		       主要的原理是通过x_request_id、span_id匹配追踪，这些信息穿越L7网关时保持不变。

		    3. 根据网络流量追踪信息追踪：
		       主要的原理是通过TCP SEQ匹配追踪，这些信息穿越L2-L4网元时保持不变。

		    4. 融合1-3的结果，并将2和3中的结果合并到1中
	*/

	// 按start_time升序，用于merge_flow
	sort.Sort(common.SortByStartTimeUs(flows))
	mergedFlows := []*model.L7TracingSpan{}
	idMap := map[string]int{}
	for i, flow := range flows {
		if MergeFlow(mergedFlows, flow) {
			continue
		}
		flow.UID = i + 1
		mergedFlows = append(mergedFlows, flow)
	}

	networkFlows := []*model.L7TracingSpan{}
	appFlows := []*model.L7TracingSpan{}
	syscallFlows := []*model.L7TracingSpan{}

	for _, flow := range mergedFlows {
		for _, id := range flow.IDs {
			idMap[id] = flow.UID
		}
		flow.Duration = flow.EndTimeUs - flow.StartTimeUs

		relatedIds := []string{}
		for _, relatedID := range flow.RelatedIDs {
			relatedSlice := strings.Split(relatedID, "-")
			if slices.Contains[string](flow.IDs, relatedSlice[0]) {
				continue
			}
			flowIndex, ok := idMap[relatedSlice[0]]
			if ok {
				if len(relatedSlice) > 1 {
					relatedIds = append(relatedIds, fmt.Sprintf("%d-%s-%s", flowIndex, relatedSlice[1], relatedSlice[0]))
				}

			}
		}
		flow.RelatedIDs = relatedIds

		if slices.Contains[string]([]string{common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_CLIENT_PROCESS}, flow.TapSide) {
			syscallFlows = append(syscallFlows, flow)
		} else if slices.Contains[string]([]string{common.TAP_SIDE_CLIENT_APP, common.TAP_SIDE_SERVER_APP}, flow.TapSide) {
			appFlows = append(appFlows, flow)
		} else {
			networkFlows = append(networkFlows, flow)
		}
	}

	// 从Flow中提取Service：一个<vtap_id, local_process_id>二元组认为是一个Service
	serviceMap := map[ServiceKey]Service{}
	for _, syscallFlow := range syscallFlows {
		if syscallFlow.TapSide != common.TAP_SIDE_SERVER_PROCESS {
			continue
		}
		localProcessID := syscallFlow.ProcessID1
		vtapID := syscallFlow.VtapID
		serviceKey := ServiceKey{
			VtapID:    vtapID,
			ProcessID: localProcessID}
		_, ok := serviceMap[serviceKey]
		if !ok {
			service := Service{TraceService: &model.TraceService{VtapID: vtapID, ProcessID: localProcessID}}
			serviceMap[serviceKey] = service
			// Service直接接收或发送的Flows
			service.AddDirectFlow(syscallFlow)
		} else {
			index := 0
			for serviceKey, _ := range serviceMap {
				if serviceKey.VtapID == vtapID && serviceKey.ProcessID == localProcessID {
					index += 1
				}
			}
			newServiceKey := ServiceKey{
				VtapID:    vtapID,
				ProcessID: localProcessID,
				Index:     index}
			service := Service{TraceService: &model.TraceService{VtapID: vtapID, ProcessID: localProcessID}}
			serviceMap[newServiceKey] = service
			service.AddDirectFlow(syscallFlow)
		}

	}

	for _, syscallFlow := range syscallFlows {
		if syscallFlow.TapSide != common.TAP_SIDE_CLIENT_PROCESS {
			continue
		}
		localProcessID := syscallFlow.ProcessID0
		vtapID := syscallFlow.VtapID
		serviceKey := ServiceKey{
			VtapID:    vtapID,
			ProcessID: localProcessID}
		index := 0
		maxStartTimeService := Service{}
		_, ok := serviceMap[serviceKey]
		if ok {
			for serviceKey, service := range serviceMap {
				if serviceKey.VtapID == vtapID && serviceKey.ProcessID == localProcessID {
					index += 1
					if service.CheckClientProcessFlow(syscallFlow) {
						if maxStartTimeService.TraceService == nil {
							maxStartTimeService = service
						} else {
							if service.TraceService.StartTimeUs > maxStartTimeService.TraceService.StartTimeUs {
								maxStartTimeService = service
							}
						}
					}
				}
			}
			if maxStartTimeService.TraceService != nil {
				maxStartTimeService.AddDirectFlow(syscallFlow)
				continue
			}
		}
		// 没有attach到service上的flow生成一个新的service
		newServiceKey := ServiceKey{
			VtapID:    vtapID,
			ProcessID: localProcessID,
			Index:     index}
		service := Service{TraceService: &model.TraceService{VtapID: vtapID, ProcessID: localProcessID}}
		serviceMap[newServiceKey] = service
		service.AddDirectFlow(syscallFlow)
	}

	// 网络span及系统span按照tcp_seq进行分组
	networks := []Network{}
	networkFlows = append(networkFlows, syscallFlows...)
	sort.Sort(common.SortByType(networkFlows))
	for _, networkFlow := range networkFlows {
		if networkFlow.ReqTcpSeq == 0 && networkFlow.RespTcpSeq == 0 {
			continue
		}
		isAdd := false
		for _, network := range networks {
			if network.AddFlow(networkFlow, NetworkDelayUs) {
				isAdd = true
			}
		}
		if !isAdd {
			network := Network{}
			network.AddFlow(networkFlow, NetworkDelayUs)
			isAdd = true
			networks = append(networks, network)
		}
	}

	// 将应用span挂到Service上
	for _, appFlow := range appFlows {
		for _, service := range serviceMap {
			if service.AttachAppFlow(appFlow) {
				break
			}
		}
	}
	common.AppFlowSetService(appFlows)

	// 获取没有系统span存在的networks分组
	netSpanIDFlows := map[string]Network{}
	for _, network := range networks {
		if !network.TraceNetwork.HasSyscall && network.TraceNetwork.SpanID != "" {
			netSpanIDFlows[network.TraceNetwork.SpanID] = network
		}
	}

	// 排序
	// 网络span排序
	// 1.网络span及系统span按照tap_side_rank进行排序
	for _, network := range networks {
		network.SortAndSetParent()
	}
	// 2. 存在span_id相同的应用span，将该网络span的parent设置为该span_id相同的应用span
	for i := len(appFlows) - 1; i >= 0; i-- {
		network, ok := netSpanIDFlows[appFlows[i].SpanID]
		if ok {
			common.SetParent(network.TraceNetwork.Flows[0], appFlows[i], "network mounted duo to span_id")
			appFlows[i].NetworkFlow = network.TraceNetwork
		}
	}
	// 应用span排序
	common.AppFlowSort(appFlows)
	// 系统span排序
	services := []Service{}
	for _, service := range serviceMap {
		services = append(services, service)
		// c-p排序
		service.ParentSet()
	}
	// s-p排序
	ServiceSort(services, appFlows)
	common.SortByXRequestID(networkFlows)
	return services, appFlows, networks
}

func ServiceSort(services []Service, appFlows []*model.L7TracingSpan) {
	appFlowsMap := map[string]*model.L7TracingSpan{}
	for _, appFlow := range appFlows {
		appFlowsMap[appFlow.SpanID] = appFlow
	}
	for _, service := range services {
		if service.TraceService.DirectFlows[0].TapSide == common.TAP_SIDE_SERVER_PROCESS {
			// 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
			if service.TraceService.DirectFlows[0].ParentAppFlow != nil {
				if service.TraceService.DirectFlows[0].Network != nil && service.TraceService.DirectFlows[0].Network.Flows[0].ParentID == 0 {
					// 存在network,且network没有parent
					common.SetParent(service.TraceService.DirectFlows[0].Network.Flows[0], service.TraceService.DirectFlows[0].ParentAppFlow, "trace mounted on app_flow due to parent_app_flow of s-p")
					continue
				} else if service.TraceService.DirectFlows[0].ParentID == 0 {
					common.SetParent(service.TraceService.DirectFlows[0], service.TraceService.DirectFlows[0].ParentAppFlow, "s-p mounted on app_flow due to parent_app_flow(has the same span_id)")
					continue
				}
			}

			serverProcessParentSpanID := service.TraceService.DirectFlows[0].ParentSpanID
			_, ok := appFlowsMap[serverProcessParentSpanID]
			if !ok {
				continue
			}
			// s-p没有c-app的parent
			if serverProcessParentSpanID == "" {
				continue
			}
			// 2. 存在span_id相同且存在parent_span_id的flow，将该系统span的parent设置为span_id等于该parent_span_id的flow
			if service.TraceService.DirectFlows[0].Network != nil && service.TraceService.DirectFlows[0].Network.Flows[0].ParentID == 0 {
				common.SetParent(service.TraceService.DirectFlows[0].Network.Flows[0],
					appFlowsMap[serverProcessParentSpanID],
					"trace mounted on parent_span of s-p(from s-app)")
				continue
			} else if service.TraceService.DirectFlows[0].ParentID == 0 {
				common.SetParent(service.TraceService.DirectFlows[0],
					appFlowsMap[serverProcessParentSpanID],
					"parent fill s-p mounted on parent_span of s-app")
				continue
			}
		}
	}
}
