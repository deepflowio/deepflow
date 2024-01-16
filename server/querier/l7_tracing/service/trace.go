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
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/Workiva/go-datastructures/rangetree"
	controller_common "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("l7_tracing")

func Tracing(args model.L7Tracing, cfg *config.QuerierConfig) (result []*model.L7TracingSpan, debug interface{}, err error) {
	maxIteration := args.MaxIteration
	if maxIteration == 0 {
		maxIteration = common.MAX_ITERATION
	}
	networkDelayUs := args.NetworkDelayUs
	if networkDelayUs == 0 {
		networkDelayUs = cfg.L7Tracing.Spec.NetworkDelayUs
	}
	ntpDelayUs := args.NtpDelayUs
	if ntpDelayUs == 0 {
		ntpDelayUs = common.NTP_DELAY_US
	}
	failedRegions := []string{}
	timeFilter := fmt.Sprintf("time>=%d AND time<=%d", args.TimeStart, args.TimeEnd)
	id := args.ID
	hasAttributes := args.HasAttributes
	debugs := &model.L7TracingDebug{}
	debug = debugs
	if id == "" {
		traceID := args.TraceID
		id, err = GetIDByTraceID(traceID, timeFilter, cfg, debugs)
		if err != nil || id == "" {
			return
		}
		args.ID = id
	}
	baseFilter := fmt.Sprintf("_id=%s", id)

	networkMetas := []L7Network{}
	syscallMetas := []string{}
	traceIDs := []string{}
	appMetas := []string{}
	xRequestMetas := []string{}
	l7FlowIDs := []string{}
	xRequests := []string{}
	relatedMap := map[string][]string{}
	thirdAppSpansAll := []*model.L7TracingSpan{}

	flowMetas, err := QueryFlowMeta(timeFilter, baseFilter, cfg, debugs)
	if err != nil || len(flowMetas) == 0 {
		return
	}
	base := fmt.Sprintf("%s-base", flowMetas[0].OriginID)
	relatedMap[flowMetas[0].OriginID] = append(relatedMap[flowMetas[0].OriginID], base)
	traceID := args.TraceID
	allowMultipleTraceIDsInTracingResult := config.Cfg.L7Tracing.Spec.AllowMultipleTraceIDsInTracingResult
	callApmApiToSupplementTrace := config.Cfg.L7Tracing.Spec.CallApmApiToSupplementTrace
	multiTraceIDs := []string{}

	for i := 0; i < maxIteration; i++ {
		filters := []string{}
		// 主动注入的追踪信息
		if !allowMultipleTraceIDsInTracingResult {
			singleTraceIDFlowMetas := []*model.L7TracingSpan{}
			for _, flowMeta := range flowMetas {
				if flowMeta.TraceID == "" {
					singleTraceIDFlowMetas = append(singleTraceIDFlowMetas, flowMeta)
				} else if traceID == "" {
					traceID = flowMeta.TraceID
					singleTraceIDFlowMetas = append(singleTraceIDFlowMetas, flowMeta)
				} else if flowMeta.TraceID == traceID {
					singleTraceIDFlowMetas = append(singleTraceIDFlowMetas, flowMeta)
				}
			}
			if traceID != "" {
				traceIDFilter := fmt.Sprintf("trace_id='%s'", traceID)
				filters = append(filters, traceIDFilter)
			}
			flowMetas = singleTraceIDFlowMetas

			if callApmApiToSupplementTrace && !slices.Contains[string](multiTraceIDs, traceID) {
				appSpans, callError := CallApmApi(traceID, cfg, debugs)
				if callError != nil {
					err = callError
					return
				}
				thirdAppSpansAll = append(thirdAppSpansAll, appSpans...)
				multiTraceIDs = append(multiTraceIDs, traceID)
				for _, appSpan := range(appSpans) {
					flowMetas = append(flowMetas, appSpan)
				}
			}
		} else {
			newTraceIDs := []string{}
			thirdAppSpans := []*model.L7TracingSpan{}
			for _, flowMeta := range flowMetas {
				if flowMeta.TraceID != "" {
					newTraceIDs = append(newTraceIDs, flowMeta.TraceID)
					if callApmApiToSupplementTrace && !slices.Contains[string](multiTraceIDs, flowMeta.TraceID) {
						appSpans, callError := CallApmApi(flowMeta.TraceID, cfg, debugs)
						if callError != nil {
							err = callError
							return
						}
						thirdAppSpans = append(thirdAppSpans, appSpans...)
						multiTraceIDs = append(multiTraceIDs, flowMeta.TraceID)
						flowMetas = append(flowMetas, appSpans...)
				}

			}
			thirdAppSpansAll = append(thirdAppSpansAll, thirdAppSpans...)
			addTraceIDs := []string{}
			addTraceIDFilters := []string{}
			for _, traceID := range(newTraceIDs) {
				if !slices.Contains[string](traceIDs, traceID) {
					addTraceIDs = append(addTraceIDs, traceID)
					traceIDs = append(traceIDs, traceID)
					traceIDFilter := fmt.Sprintf("trace_id='%s'", traceID)
					if !slices.Contains[string](addTraceIDFilters, traceIDFilter) {
						addTraceIDFilters = append(addTraceIDFilters, traceIDFilter)
					}
				}
			}
			addTraceIDFilterStr := strings.Join(addTraceIDFilters, " OR ")
			filters = append(filters, addTraceIDFilterStr)
		}

		// 新的网络追踪信息
		newL7NetworkMetas := []L7Network{}
		for _, flowMeta := range flowMetas {
			if flowMeta.ReqTcpSeq == 0 && flowMeta.RespTcpSeq == 0 {
				continue
			}
			if !slices.Contains[string]([]string{common.TAP_SIDE_CLIENT_PROCESS,common.TAP_SIDE_SERVER_PROCESS},flowMeta.TapSide) {
				_, ok := common.TAP_SIDE_RANKS[flowMeta.TapSide]
				if !ok {
					continue
				}
			}
			l7Network := L7Network{}
			l7Network.L7NetworkMeta.ID = flowMeta.OriginID
			l7Network.L7NetworkMeta.Type = flowMeta.Type
			l7Network.L7NetworkMeta.ReqTcpSeq = flowMeta.ReqTcpSeq
			l7Network.L7NetworkMeta.RespTcpSeq = flowMeta.RespTcpSeq
			l7Network.L7NetworkMeta.StartTimeUs = flowMeta.StartTimeUs
			l7Network.L7NetworkMeta.EndTimeUs = flowMeta.EndTimeUs
			l7Network.L7NetworkMeta.SpanID = flowMeta.SpanID
			l7Network.L7NetworkMeta.NetworkDelayUs = networkDelayUs
			newL7NetworkMetas = append(newL7NetworkMetas, l7Network)
		}
		addL7NetworkMetas := []L7Network{}
		addL7NetworkFilters := []string{}
		for _, newL7NetworkMeta := range(newL7NetworkMetas) {
			if !slices.Contains[L7Network](networkMetas, newL7NetworkMeta) {
				addL7NetworkMetas = append(addL7NetworkMetas, newL7NetworkMeta)
				networkMetas = append(networkMetas, newL7NetworkMeta)
				l7NetworkMetaFilter := newL7NetworkMeta.ToSqlFilter()
				if !slices.Contains[string](addL7NetworkFilters, l7NetworkMetaFilter) {
					addL7NetworkFilters = append(addL7NetworkFilters, l7NetworkMetaFilter)
				}
			}
		}
		networkFilterStr := fmt.Sprintf("(%s) AND (resp_tcp_seq!=0 OR req_tcp_seq!=0)", strings.Join(addL7NetworkFilters, " OR "))
		filters = append(filters, networkFilterStr)

		// 新的系统调用追踪信息
		newL7SyscallMetas := []L7Syscall{}
		for _, flowMeta := range flowMetas {
			if flowMeta.SyscallTraceIDRequest == 0 && flowMeta.SyscallTraceIDResponse == 0 {
				continue
			}
			l7Syscall := L7Syscall{}
			l7Syscall.L7SyscallMeta.ID = flowMeta.OriginID
			l7Syscall.L7SyscallMeta.VtapID = flowMeta.VtapID
			l7Syscall.L7SyscallMeta.SyscallTraceIDRequest = flowMeta.SyscallTraceIDRequest
			l7Syscall.L7SyscallMeta.SyscallTraceIDResponse = flowMeta.SyscallTraceIDResponse
			l7Syscall.L7SyscallMeta.StartTimeUs = flowMeta.StartTimeUs
			l7Syscall.L7SyscallMeta.EndTimeUs = flowMeta.EndTimeUs
			l7Syscall.L7SyscallMeta.TapSide = flowMeta.TapSide
			newL7SyscallMetas = append(newL7SyscallMetas, l7Syscall)
		}
		addL7SyscallMetas := []L7Syscall{}
		addL7SyscallFilters := []string{}
		for _, newL7SyscallMeta := range(newL7SyscallMetas) {
			if !slices.Contains[L7Syscall](syscallMetas, newL7SyscallMeta) {
				addL7SyscallMetas = append(addL7SyscallMetas, newL7SyscallMeta)
				syscallMetas = append(syscallMetas, newL7SyscallMeta)
				l7SyscallMetaFilter := newL7SyscallMeta.ToSqlFilter()
				if !slices.Contains[string](addL7SyscallFilters, l7SyscallMetaFilter) {
					addL7SyscallFilters = append(addL7SyscallFilters, l7SyscallMetaFilter)
				}
			}
		}
		syscallFilterStr := fmt.Sprintf("(%s)", strings.Join(addL7SyscallFilters, " OR "))
		filters = append(filters, syscallFilterStr)

		// 新的应用span追踪信息
		newL7AppMetas := []L7App{}
		for _, flowMeta := range flowMetas {
			if !slices.Contains[string]([]string{common.TAP_SIDE_CLIENT_PROCESS,common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_APP,common.TAP_SIDE_CLIENT_APP,common.TAP_SIDE_SERVER_APP},flowMeta.TapSide) && flowMeta.SpanID==""{
				continue
			}
			if flowMeta.SpanID == "" || flowMeta.ParentSpanID == "" {
				continue
			}
			l7App := L7App{}
			l7App.L7AppMeta.ID = flowMeta.OriginID
			l7App.L7AppMeta.TapSide = flowMeta.TapSide
			l7App.L7AppMeta.SpanID = flowMeta.SpanID
			l7App.L7AppMeta.ParentSpanID = flowMeta.ParentSpanID
			newL7AppMetas = append(newL7AppMetas, l7App)
		}
		addL7AppMetas := []L7App{}
		addL7AppFilters := []string{}
		for _, newL7AppMeta := range(newL7AppMetas) {
			if !slices.Contains[L7App](appMetas, newL7AppMeta) {
				addL7AppMetas = append(addL7AppMetas, newL7AppMeta)
				appMetas = append(appMetas, newL7AppMeta)
				l7AppMetaFilter := newL7AppMeta.ToSqlFilter()
				if !slices.Contains[string](addL7AppFilters, l7AppMetaFilter) {
					addL7AppFilters = append(addL7AppFilters, l7AppMetaFilter)
				}
				
			}
		}
		appFilterStr := fmt.Sprintf("(%s)", strings.Join(addL7AppFilters, " OR "))
		filters = append(filters, appFilterStr)

		// 新的x_request_id关联span追踪信息
		newL7XRequestMetas := []L7XRequest{}
		for _, flowMeta := range flowMetas {
			if flowMeta.XRequestID0 == "" && flowMeta.XRequestID1 == "" {
				continue
			}
			l7XRequest := L7XRequest{}
			l7XRequest.L7XRequestMeta.ID = flowMeta.OriginID
			l7XRequest.L7XRequestMeta.XRequestID0 = flowMeta.XRequestID0
			l7XRequest.L7XRequestMeta.XRequestID1 = flowMeta.XRequestID1
			newL7XRequestMetas = append(newL7XRequestMetas, l7XRequest)
		}
		addL7XRequestMetas := []L7XRequest{}
		addL7XRequestFilters := []string{}
		for _, newL7XRequestMeta := range(newL7XRequestMetas) {
			if !slices.Contains[L7XRequest](appMetas, newL7XRequestMeta) {
				addL7XRequestMetas = append(addL7XRequestMetas, newL7XRequestMeta)
				appMetas = append(appMetas, newL7XRequestMeta)
				l7XRequestMetaFilter := newL7XRequestMeta.ToSqlFilter()
				addL7XRequestFilters = append(addL7XRequestFilters, l7XRequestMetaFilter)
			}
		}
		xRequestFilterStr := fmt.Sprintf("(%s)", strings.Join(addL7XRequestFilters, " OR "))
		filters = append(filters, xRequestFilterStr)

		if len(filters) == 0 {
			break
		}
		newFlows := []*model.L7TracingSpan{}
		var newFlowsError error
		if !allowMultipleTraceIDsInTracingResult && traceID != "" {
			newFilters := []string{}
			newFilters = append(newFilters, fmt.Sprintf("(%s)", strings.Join(filters, " OR ")))
			newFilters = append(newFilters, fmt.Sprintf("(trace_id='%s' OR trace_id='')", traceID))
			newFiltersStr := fmt.Sprintf("(%s)", strings.Join(newFilters, " AND "))
			newFlows, err = QueryFlowMeta(timeFilter,newFiltersStr,cfg, debugs)
		} else {
			newFlows, err = QueryFlowMeta(timeFilter,fmt.Sprintf("(%s)", strings.Join(filters, " OR ")),cfg, debugs)
		}
		if err != nil {
			return
		}
		if len(newFlows) == 0 {
			break
		}
		for _, addL7XRequestMeta := range(addL7XRequestMetas) {
			addL7XRequestMeta.SetRelate(newFlows,relatedMap)
		}
		for _, addL7SyscallMeta := range(addL7SyscallMetas) {
			addL7SyscallMeta.SetRelate(newFlows,relatedMap)
		}
		for _, addL7NetworkMeta := range(addL7NetworkMetas) {
			addL7NetworkMeta.SetRelate(newFlows,relatedMap)
		}
		for _, addL7AppMeta := range(addL7AppMetas) {
			addL7AppMeta.SetRelate(newFlows,relatedMap)
		}
		flowMetaIDs := []string{}
		for _, flowMeta := range(flowMetas) {
			if !slices.Contains[string](flowMetaIDs, flowMeta.OriginID) {
				flowMetaIDs = append(flowMetaIDs, flowMeta.OriginID)
			}
		}
		newFlowIDs := []string{}
		for _, newFlow := range(newFlows) {
			if !slices.Contains[string](flowMetaIDs, newFlow.OriginID) {
				flowMetas = append(flowMetas, newFlow)
				newFlowIDs = append(newFlowIDs, newFlow.OriginID)
			}
		}
		if len(newFlowIDs) == 0 {
			break
		}
		l7FlowIDS = append(l7FlowIDS, flowMetaIDs...)
		l7FlowIDS = append(l7FlowIDS, newFlowIDs...)
	}

	if len(l7FlowIDs) == 0 {
		return
	}
	// 获取追踪到的所有应用流日志
	returnFields:=[]string{"related_ids"}
	returnFields = append(returnFields, common.RETURN_FIELDS...)
	flowFields :=  common.RETURN_FIELDS
	if hasAttributes {
		returnFields = append(returnFields, "attribute")
		flowFields = append(flowFields, "attribute")
	}
	l7Flows, err := QueryAllFlow(timeFilter,l7FlowIDs,flowFields,debugs)
	if err != nil {
		return
	}


	// # 获取追踪到的所有应用流日志
	// return_fields += RETURN_FIELDS
	// flow_fields = list(RETURN_FIELDS)
	// if self.has_attributes:
	// 	return_fields.append("attribute")
	// 	flow_fields.append("attribute")
	// l7_flows = await self.query_all_flows(time_filter, l7_flow_ids,
	// 									  flow_fields)
	// if type(l7_flows) != DataFrame:
	// 	return {}
	// l7_flows.rename(columns={'_id_str': '_id'}, inplace=True)
	// l7_flows = pd.concat(
	// 	[l7_flows, pd.DataFrame(third_app_spans_all)],
	// 	join="outer",
	// 	ignore_index=True).drop_duplicates(["_id"]).reset_index(drop=True)
	// l7_flows.insert(0, "related_ids", "")
	// l7_flows = l7_flows.where(l7_flows.notnull(), None)
	// for index in range(len(l7_flows.index)):
	// 	l7_flows["related_ids"][index] = related_map[l7_flows._id[index]]
	// # 对所有应用流日志排序
	// l7_flows_merged, app_flows, networks = sort_all_flows(
	// 	l7_flows, network_delay_us, return_fields, ntp_delay_us)
	

	return
}

func GetIDByTraceID(traceID, timeFilter string, cfg *config.QuerierConfig, debugs *model.L7TracingDebug) (id string, err error) {
	url := fmt.Sprintf("http://%s/v1/query/?debug=true", net.JoinHostPort("localhost", fmt.Sprintf("%d", cfg.ListenPort)))
	body := map[string]interface{}{}
	body["db"] = common.DATABASE_FLOW_LOG
	sql := fmt.Sprintf(
		"SELECT _id FROM l7_flow_log WHERE trace_id='%s' AND %s limit 1",
		traceID, timeFilter,
	)
	body["sql"] = sql
	resp, err := controller_common.CURLPerform("POST", url, body)
	if err != nil {
		log.Errorf("query _id failed: %s; sql: %s", err.Error(), sql)
		return id, err
	}
	idDebug := model.Debug{}
	idDebug.Sql = sql
	idDebug.IP = resp.Get("debug").Get("ip").MustString()
	idDebug.QueryUUID = resp.Get("debug").Get("query_uuid").MustString()
	idDebug.SqlCH = resp.Get("debug").Get("sql").MustString()
	idDebug.Error = resp.Get("debug").Get("error").MustString()
	idDebug.QueryTime = resp.Get("debug").Get("query_time").MustString()
	debugs.QuerierDebug = append(debugs.QuerierDebug, idDebug)
	if len(resp.Get("result").MustMap()) == 0 {
		log.Warningf("no data in query _id: %s", sql)
		return id, err
	}
	idIndex := -1
	columns := resp.GetPath("result", "columns")
	values := resp.GetPath("result", "values")
	for columnIndex := range columns.MustArray() {
		column := columns.GetIndex(columnIndex).MustString()
		if column == "_id" {
			idIndex = columnIndex
		}
	}
	for valueIndex := range values.MustArray() {
		idUint64 := values.GetIndex(valueIndex).GetIndex(idIndex).MustUint64()
		id = strconv.FormatUint(idUint64, 10)
	}
	return id, err
}

func QueryFlowMeta(timeFilter, baseFilter string, cfg *config.QuerierConfig, debugs *model.L7TracingDebug) (result []*model.L7TracingSpan, err error) {
	/*
		找到base_filter对应的L7 Flowmeta
		网络流量追踪信息：
			type, req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us
			通过tcp_seq及流日志的时间追踪
		系统调用追踪信息：
			vtap_id, syscall_trace_id_request, syscall_trace_id_response
			通过eBPF获取到的coroutine_trace_id追踪
		主动注入的追踪信息：
			trace_id：通过Tracing SDK主动注入的trace_id追踪
			x_request_id_0：通过Nginx/HAProxy/BFE等L7网关注入的requst_id追踪
			x_request_id_1：通过Nginx/HAProxy/BFE等L7网关注入的requst_id追踪
	*/
	url := fmt.Sprintf("http://%s/v1/query/?debug=true", net.JoinHostPort("localhost", fmt.Sprintf("%d", cfg.ListenPort)))
	body := map[string]interface{}{}
	body["db"] = common.DATABASE_FLOW_LOG
	sql := fmt.Sprintf(`SELECT 
		type, req_tcp_seq, resp_tcp_seq, toUnixTimestamp64Micro(start_time) AS start_time_us, toUnixTimestamp64Micro(end_time) AS end_time_us, 
		vtap_id, syscall_trace_id_request, syscall_trace_id_response, span_id, parent_span_id, l7_protocol, 
		trace_id, x_request_id_0, x_request_id_1, _id, tap_side, auto_instance_0, auto_instance_1
		FROM l7_flow_log
		WHERE ((%s) AND (%s)) limit %d`, timeFilter, baseFilter, cfg.L7Tracing.Spec.L7TracingLimit)
	body["sql"] = sql
	resp, err := controller_common.CURLPerform("POST", url, body)
	if err != nil {
		log.Errorf("query flowmeta failed: %s; sql: %s", err.Error(), sql)
		return
	}
	flowMetaDebug := model.Debug{}
	flowMetaDebug.Sql = sql
	flowMetaDebug.IP = resp.Get("debug").Get("ip").MustString()
	flowMetaDebug.QueryUUID = resp.Get("debug").Get("query_uuid").MustString()
	flowMetaDebug.SqlCH = resp.Get("debug").Get("sql").MustString()
	flowMetaDebug.Error = resp.Get("debug").Get("error").MustString()
	flowMetaDebug.QueryTime = resp.Get("debug").Get("query_time").MustString()
	debugs.QuerierDebug = append(debugs.QuerierDebug, flowMetaDebug)
	if len(resp.Get("result").MustMap()) == 0 {
		log.Warningf("no data in query flowmeta: %s", sql)
		return
	}
	typeIndex := -1
	reqTcpSeqIndex := -1
	respTcpSeqIndex := -1
	startTimeUsIndex := -1
	endTimeUsIndex := -1
	vtapIDIndex := -1
	syscallTraceIDRequestIndex := -1
	syscallTraceIDResponseIndex := -1
	spanIDIndex := -1
	parentSpanIDIndex := -1
	l7ProtocolIndex := -1
	traceIDIndex := -1
	xRequestID0Index := -1
	xRequestID1Index := -1
	idIndex := -1
	tapSideIndex := -1
	autoInstance0Index := -1
	autoInstance1Index := -1
	columns := resp.GetPath("result", "columns")
	values := resp.GetPath("result", "values")
	for columnIndex := range columns.MustArray() {
		column := columns.GetIndex(columnIndex).MustString()
		switch column {
		case "type":
			typeIndex = columnIndex
		case "req_tcp_seq":
			reqTcpSeqIndex = columnIndex
		case "resp_tcp_seq":
			respTcpSeqIndex = columnIndex
		case "start_time_us":
			startTimeUsIndex = columnIndex
		case "end_time_us":
			endTimeUsIndex = columnIndex
		case "vtap_id":
			vtapIDIndex = columnIndex
		case "syscall_trace_id_request":
			syscallTraceIDRequestIndex = columnIndex
		case "syscall_trace_id_response":
			syscallTraceIDResponseIndex = columnIndex
		case "span_id":
			spanIDIndex = columnIndex
		case "parent_span_id":
			parentSpanIDIndex = columnIndex
		case "l7_protocol":
			l7ProtocolIndex = columnIndex
		case "trace_id":
			traceIDIndex = columnIndex
		case "x_request_id_0":
			xRequestID0Index = columnIndex
		case "x_request_id_1":
			xRequestID1Index = columnIndex
		case "_id":
			idIndex = columnIndex
		case "tap_side":
			tapSideIndex = columnIndex
		case "auto_instance_0":
			autoInstance0Index = columnIndex
		case "auto_instance_1":
			autoInstance1Index = columnIndex
		}
	}
	for valueIndex := range values.MustArray() {
		tp := values.GetIndex(valueIndex).GetIndex(typeIndex).MustInt()
		reqTcpSeq := values.GetIndex(valueIndex).GetIndex(reqTcpSeqIndex).MustInt()
		respTcpSeq := values.GetIndex(valueIndex).GetIndex(respTcpSeqIndex).MustInt()
		startTimeUs := values.GetIndex(valueIndex).GetIndex(startTimeUsIndex).MustInt()
		endTimeUs := values.GetIndex(valueIndex).GetIndex(endTimeUsIndex).MustInt()
		vtapID := values.GetIndex(valueIndex).GetIndex(vtapIDIndex).MustInt()
		syscallTraceIDRequestUint64 := values.GetIndex(valueIndex).GetIndex(syscallTraceIDRequestIndex).MustUint64()
		syscallTraceIDRequest := strconv.FormatUint(syscallTraceIDRequestUint64, 10)
		syscallTraceIDResponseUint64 := values.GetIndex(valueIndex).GetIndex(syscallTraceIDResponseIndex).MustUint64()
		syscallTraceIDResponse := strconv.FormatUint(syscallTraceIDResponseUint64, 10)
		spanID := values.GetIndex(valueIndex).GetIndex(spanIDIndex).MustString()
		parentSpanID := values.GetIndex(valueIndex).GetIndex(parentSpanIDIndex).MustString()
		l7Protocol := values.GetIndex(valueIndex).GetIndex(l7ProtocolIndex).MustInt()
		traceID := values.GetIndex(valueIndex).GetIndex(traceIDIndex).MustString()
		xRequestID0 := values.GetIndex(valueIndex).GetIndex(xRequestID0Index).MustString()
		xRequestID1 := values.GetIndex(valueIndex).GetIndex(xRequestID1Index).MustString()
		idUint64 := values.GetIndex(valueIndex).GetIndex(idIndex).MustUint64()
		id := strconv.FormatUint(idUint64, 10)
		tapSide := values.GetIndex(valueIndex).GetIndex(tapSideIndex).MustString()
		autoInstance0 := values.GetIndex(valueIndex).GetIndex(autoInstance0Index).MustString()
		autoInstance1 := values.GetIndex(valueIndex).GetIndex(autoInstance1Index).MustString()
		l7TracingSpan := &model.L7TracingSpan{}
		l7TracingSpan.Type = tp
		l7TracingSpan.ReqTcpSeq = reqTcpSeq
		l7TracingSpan.RespTcpSeq = respTcpSeq
		l7TracingSpan.StartTimeUs = startTimeUs
		l7TracingSpan.EndTimeUs = endTimeUs
		l7TracingSpan.VtapID = vtapID
		l7TracingSpan.SyscallTraceIDRequest = syscallTraceIDRequest
		l7TracingSpan.SyscallTraceIDResponse = syscallTraceIDResponse
		l7TracingSpan.SpanID = spanID
		l7TracingSpan.ParentSpanID = parentSpanID
		l7TracingSpan.L7Protocol = l7Protocol
		l7TracingSpan.TraceID = traceID
		l7TracingSpan.XRequestID0 = xRequestID0
		l7TracingSpan.XRequestID1 = xRequestID1
		l7TracingSpan.OriginID = id
		l7TracingSpan.TapSide = tapSide
		l7TracingSpan.AutoInstance0 = autoInstance0
		l7TracingSpan.AutoInstance1 = autoInstance1
		result = append(result, l7TracingSpan)
	}
	return
}

func QueryAllFlow(timeFilter, ids, returnFields []string, debugs *model.L7TracingDebug) (result []*model.L7TracingSpan, err error) {
	/*
        根据l7_flow_ids查询所有追踪到的应用流日志
		if(is_ipv4, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0,
		if(is_ipv4, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1)) AS ip_1,
		toUnixTimestamp64Micro(start_time) AS start_time_us,
		toUnixTimestamp64Micro(end_time) AS end_time_us,
		dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_0))) AS epc_name_0,
		dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_1))) AS epc_name_1,
		dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_0),toUInt64(l3_device_id_0))) AS l3_device_name_0,
		dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_1),toUInt64(l3_device_id_1))) AS l3_device_name_1,
		dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_0))) AS pod_name_0,
		dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_1))) AS pod_name_1,
		dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_0))) AS pod_node_name_0,
		dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_1))) AS pod_node_name_1
	*/
	url := fmt.Sprintf("http://%s/v1/query/?debug=true", net.JoinHostPort("localhost", fmt.Sprintf("%d", cfg.ListenPort)))
	body := map[string]interface{}{}
	body["db"] = common.DATABASE_FLOW_LOG
	idsFilter := []string{}
	for _, id := range(ids) {
		idsFilter = append(idsFilter, fmt.Sprintf("_id=%s", id))
	}
	idsFilterStr := strings.Join(idsFilter, " OR ")
	fields := []string{}
	for _, returnField := range(returnFields) {
		transField, ok := common.FIELDS_MAP[returnField]
		if ok {
			fields = append(fields, transField)
		} else {
			fields = append(fields, returnField)
		}
	}
	fieldsStr := strings.Join(fields, ", ")
	sql = fmt.Sprintf("SELECT %s FROM `l7_flow_log` WHERE ((%s) AND (%s)) ORDER BY start_time_us asc",fieldsStr,timeFilter,idsFilterStr)
	body["sql"] = sql
	resp, err := controller_common.CURLPerform("POST", url, body)
	if err != nil {
		log.Errorf("query flowmeta failed: %s; sql: %s", err.Error(), sql)
		return
	}
	allFlowDebug := model.Debug{}
	allFlowDebug.Sql = sql
	allFlowDebug.IP = resp.Get("debug").Get("ip").MustString()
	allFlowDebug.QueryUUID = resp.Get("debug").Get("query_uuid").MustString()
	allFlowDebug.SqlCH = resp.Get("debug").Get("sql").MustString()
	allFlowDebug.Error = resp.Get("debug").Get("error").MustString()
	allFlowDebug.QueryTime = resp.Get("debug").Get("query_time").MustString()
	debugs.QuerierDebug = append(debugs.QuerierDebug, allFlowDebug)
	if len(resp.Get("result").MustMap()) == 0 {
		log.Warningf("no data in query all flow: %s", sql)
		return
	}
	typeIndex := -1
	reqTcpSeqIndex := -1
	respTcpSeqIndex := -1
	startTimeUsIndex := -1
	endTimeUsIndex := -1
	vtapIDIndex := -1
	tapPortIndex := -1
	tapPortNameIndex := -1
	tapPortTypeIndex := -1
	resourceFromVtapIndex := -1
	syscallTraceIDRequestIndex := -1
	syscallTraceIDResponseIndex := -1
	spanIDIndex := -1
	parentSpanIDIndex := -1
	l7ProtocolIndex := -1
	l7ProtocolStrIndex := -1
	traceIDIndex := -1
	xRequestID0Index := -1
	xRequestID1Index := -1
	idIndex := -1
	flowIDIndex := -1
	protocolIndex := -1
	versionIndex := -1
	tapSideIndex := -1
	autoInstance0Index := -1
	autoInstance1Index := -1
	columns := resp.GetPath("result", "columns")
	values := resp.GetPath("result", "values")
	for columnIndex := range columns.MustArray() {
		column := columns.GetIndex(columnIndex).MustString()
		switch column {
		case "type":
			typeIndex = columnIndex
		case "req_tcp_seq":
			reqTcpSeqIndex = columnIndex
		case "resp_tcp_seq":
			respTcpSeqIndex = columnIndex
		case "start_time_us":
			startTimeUsIndex = columnIndex
		case "end_time_us":
			endTimeUsIndex = columnIndex
		case "vtap_id":
			vtapIDIndex = columnIndex
		case "tap_port":
			tapPortIndex = columnIndex
		case "tap_port_name":
			tapPortNameIndex = columnIndex
		case "tap_port_type":
			tapPortTypeIndex = columnIndex
		case "resource_from_vtap":
			resourceFromVtapIndex = columnIndex
		case "syscall_trace_id_request":
			syscallTraceIDRequestIndex = columnIndex
		case "syscall_trace_id_response":
			syscallTraceIDResponseIndex = columnIndex
		case "syscall_cap_seq_0":
			SyscallCapSeq0Index = columnIndex
		case "syscall_cap_seq_1":
			SyscallCapSeq1Index = columnIndex
		case "span_id":
			spanIDIndex = columnIndex
		case "parent_span_id":
			parentSpanIDIndex = columnIndex
		case "l7_protocol":
			l7ProtocolIndex = columnIndex
		case "l7_protocol_str":
			l7ProtocolStrIndex = columnIndex
		case "trace_id":
			traceIDIndex = columnIndex
		case "x_request_id_0":
			xRequestID0Index = columnIndex
		case "x_request_id_1":
			xRequestID1Index = columnIndex
		case "_id":
			idIndex = columnIndex
		case "flow_id":
			flowIDIndex = columnIndex
		case "protocol":
			protocolIndex = columnIndex
		case "version":
			versionIndex = columnIndex
		case "tap_side":
			tapSideIndex = columnIndex
		case "auto_instance_0":
			autoInstance0Index = columnIndex
		case "auto_instance_1":
			autoInstance1Index = columnIndex
		}
	}
	for valueIndex := range values.MustArray() {
		tp := values.GetIndex(valueIndex).GetIndex(typeIndex).MustInt()
		reqTcpSeq := values.GetIndex(valueIndex).GetIndex(reqTcpSeqIndex).MustInt()
		respTcpSeq := values.GetIndex(valueIndex).GetIndex(respTcpSeqIndex).MustInt()
		startTimeUs := values.GetIndex(valueIndex).GetIndex(startTimeUsIndex).MustInt()
		endTimeUs := values.GetIndex(valueIndex).GetIndex(endTimeUsIndex).MustInt()
		vtapID := values.GetIndex(valueIndex).GetIndex(vtapIDIndex).MustInt()
		tapPort := values.GetIndex(valueIndex).GetIndex(tapPortIndex).MustInt()
		tapPortName := values.GetIndex(valueIndex).GetIndex(tapPortNameIndex).MustString()
		tapPortType := values.GetIndex(valueIndex).GetIndex(tapPortTypeIndex).MustInt()
		resourceFromVtapDeviceType := values.GetIndex(valueIndex).GetIndex(resourceFromVtapIndex).GetIndex(0).MustInt()
		resourceFromVtapDeviceName := values.GetIndex(valueIndex).GetIndex(resourceFromVtapIndex).GetIndex(2).MustString()
		resourceFromVtap := ""
		if resourceFromVtapDeviceType != 0 {
			resourceFromVtap = resourceFromVtapDeviceName
		}
		syscallTraceIDRequestUint64 := values.GetIndex(valueIndex).GetIndex(syscallTraceIDRequestIndex).MustUint64()
		syscallTraceIDRequest := strconv.FormatUint(syscallTraceIDRequestUint64, 10)
		syscallTraceIDResponseUint64 := values.GetIndex(valueIndex).GetIndex(syscallTraceIDResponseIndex).MustUint64()
		syscallTraceIDResponse := strconv.FormatUint(syscallTraceIDResponseUint64, 10)
		syscallCapSeq0 := values.GetIndex(valueIndex).GetIndex(SyscallCapSeq0Index).MustInt()
		syscallCapSeq1 := values.GetIndex(valueIndex).GetIndex(SyscallCapSeq1Index).MustInt()
		spanID := values.GetIndex(valueIndex).GetIndex(spanIDIndex).MustString()
		parentSpanID := values.GetIndex(valueIndex).GetIndex(parentSpanIDIndex).MustString()
		l7Protocol := values.GetIndex(valueIndex).GetIndex(l7ProtocolIndex).MustInt()
		l7ProtocolStr := values.GetIndex(valueIndex).GetIndex(l7ProtocolStrIndex).MustString()
		traceID := values.GetIndex(valueIndex).GetIndex(traceIDIndex).MustString()
		xRequestID0 := values.GetIndex(valueIndex).GetIndex(xRequestID0Index).MustString()
		xRequestID1 := values.GetIndex(valueIndex).GetIndex(xRequestID1Index).MustString()
		idUint64 := values.GetIndex(valueIndex).GetIndex(idIndex).MustUint64()
		id := strconv.FormatUint(idUint64, 10)
		flowIDUint64 := values.GetIndex(valueIndex).GetIndex(flowIDIndex).MustUint64()
		flowID := strconv.FormatUint(flowIDUint64, 10)
		protocol := values.GetIndex(valueIndex).GetIndex(protocolIndex).MustInt()
		version := values.GetIndex(valueIndex).GetIndex(versionIndex).MustString()
		tapSide := values.GetIndex(valueIndex).GetIndex(tapSideIndex).MustString()
		autoInstance0 := values.GetIndex(valueIndex).GetIndex(autoInstance0Index).MustString()
		autoInstance1 := values.GetIndex(valueIndex).GetIndex(autoInstance1Index).MustString()
		l7TracingSpan := &model.L7TracingSpan{}
		l7TracingSpan.Type = tp
		l7TracingSpan.ReqTcpSeq = reqTcpSeq
		l7TracingSpan.RespTcpSeq = respTcpSeq
		l7TracingSpan.StartTimeUs = startTimeUs
		l7TracingSpan.EndTimeUs = endTimeUs
		l7TracingSpan.VtapID = vtapID
		l7TracingSpan.TapPort = TapPort
		l7TracingSpan.TapPortName = TapPortName
		l7TracingSpan.TapPortType = TapPortType
		l7TracingSpan.ResourceFromVtap = ResourceFromVtap
		l7TracingSpan.SyscallTraceIDRequest = syscallTraceIDRequest
		l7TracingSpan.SyscallTraceIDResponse = syscallTraceIDResponse
		l7TracingSpan.SyscallCapSeq0 = syscallCapSeq0
		l7TracingSpan.SyscallCapSeq1 = syscallCapSeq1
		l7TracingSpan.SpanID = spanID
		l7TracingSpan.ParentSpanID = parentSpanID
		l7TracingSpan.L7Protocol = l7Protocol
		l7TracingSpan.L7ProtocolStr = l7ProtocolStr
		l7TracingSpan.TraceID = traceID
		l7TracingSpan.XRequestID0 = xRequestID0
		l7TracingSpan.XRequestID1 = xRequestID1
		l7TracingSpan.OriginID = id
		l7TracingSpan.FlowID = flowID
		l7TracingSpan.Protocol = protocol
		l7TracingSpan.Version = version
		l7TracingSpan.TapSide = tapSide
		l7TracingSpan.AutoInstance0 = autoInstance0
		l7TracingSpan.AutoInstance1 = autoInstance1
		result = append(result, l7TracingSpan)
	}
	return
}

func CallApmApi(traceID string, cfg *config.QuerierConfig, debugs *model.L7TracingDebug) (result []*model.L7TracingSpan, err error) {
	url := fmt.Sprintf("http://%s/api/v1/adapter/tracing?traceid=%s", net.JoinHostPort("localhost", fmt.Sprintf("%d", cfg.ListenPort)), traceID)
	body := map[string]interface{}{}
	startTime := time.Now()

	resp, err := controller_common.CURLPerform("GET", url, body)
	endTime := int64(time.Since(startTime))
	time := fmt.Sprintf("%.9fs", float64(endTime)/1e9)
	callApmDebug := model.CurlDebug{}
	callApmDebug.Url = url
	callApmDebug.Time = time
	callApmDebug.Error = err.Error()
	debugs.CallDebug = append(debugs.CallDebug, callApmDebug)
	if err != nil {
		log.Errorf("call apm api failed: %s; url: %s", err.Error(), url)
		return
	}
	spans := resp.Get("data").Get("spans").MustArray()
	if len(spans) == 0 {
		log.Warningf("no data in call apm api: %s", url)
		return
	}
	idIndex := -1
	startTimeUsIndex := -1
	endTimeUsIndex := -1
	tapSideIndex := -1
	l7ProtocolIndex := -1
	l7ProtocolStrIndex := -1
	traceIDIndex := -1
	spanIDIndex := -1
	parentSpanIDIndex := -1
	endpointIndex := -1
	requestTypeIndex := -1
	requestResourceIndex := -1
	responseStatusIndex := -1
	appServiceIndex := -1
	appInstanceIndex := -1
	serviceUnameIndex := -1
	columns := resp.GetPath("result", "columns")
	values := resp.GetPath("result", "values")
	for columnIndex := range columns.MustArray() {
		column := columns.GetIndex(columnIndex).MustString()
		switch column {
		case "l7_protocol_str":
			l7ProtocolStrIndex = columnIndex
		case "endpoint":
			endpointIndex = columnIndex
		case "request_type":
			requestTypeIndex = columnIndex
		case "start_time_us":
			startTimeUsIndex = columnIndex
		case "end_time_us":
			endTimeUsIndex = columnIndex
		case "request_resource":
			requestResourceIndex = columnIndex
		case "response_status":
			responseStatusIndex = columnIndex
		case "app_service":
			appServiceIndex = columnIndex
		case "span_id":
			spanIDIndex = columnIndex
		case "parent_span_id":
			parentSpanIDIndex = columnIndex
		case "l7_protocol":
			l7ProtocolIndex = columnIndex
		case "trace_id":
			traceIDIndex = columnIndex
		case "app_instance":
			appInstanceIndex = columnIndex
		case "service_uname":
			serviceUnameIndex = columnIndex
		case "_id":
			idIndex = columnIndex
		case "tap_side":
			tapSideIndex = columnIndex
		}
	}
	for valueIndex := range values.MustArray() {
		l7ProtocolStr := values.GetIndex(valueIndex).GetIndex(l7ProtocolStrIndex).MustString()
		endpoint := values.GetIndex(valueIndex).GetIndex(endpointIndex).MustString()
		requestType := values.GetIndex(valueIndex).GetIndex(requestTypeIndex).MustString()
		startTimeUs := values.GetIndex(valueIndex).GetIndex(startTimeUsIndex).MustInt()
		endTimeUs := values.GetIndex(valueIndex).GetIndex(endTimeUsIndex).MustInt()
		requestResource := values.GetIndex(valueIndex).GetIndex(requestResourceIndex).MustString()
		responseStatus := values.GetIndex(valueIndex).GetIndex(responseStatusIndex).MustInt()
		appService := values.GetIndex(valueIndex).GetIndex(appServiceIndex).MustString()
		spanID := values.GetIndex(valueIndex).GetIndex(spanIDIndex).MustString()
		parentSpanID := values.GetIndex(valueIndex).GetIndex(parentSpanIDIndex).MustString()
		l7Protocol := values.GetIndex(valueIndex).GetIndex(l7ProtocolIndex).MustInt()
		traceID := values.GetIndex(valueIndex).GetIndex(traceIDIndex).MustString()
		appInstance := values.GetIndex(valueIndex).GetIndex(appInstanceIndex).MustString()
		serviceUname := values.GetIndex(valueIndex).GetIndex(serviceUnameIndex).MustString()
		idUint64 := values.GetIndex(valueIndex).GetIndex(idIndex).MustUint64()
		id := strconv.FormatUint(idUint64, 10)
		tapSide := values.GetIndex(valueIndex).GetIndex(tapSideIndex).MustString()
		l7TracingSpan := &model.L7TracingSpan{}
		l7TracingSpan.L7ProtocolStr = l7ProtocolStr
		l7TracingSpan.Endpoint = endpoint
		l7TracingSpan.RequestType = requestType
		l7TracingSpan.StartTimeUs = startTimeUs
		l7TracingSpan.EndTimeUs = endTimeUs
		l7TracingSpan.RequestResource = requestResource
		l7TracingSpan.AppService = appService
		l7TracingSpan.AppInstance = appInstance
		l7TracingSpan.SpanID = spanID
		l7TracingSpan.ParentSpanID = parentSpanID
		l7TracingSpan.L7Protocol = l7Protocol
		l7TracingSpan.TraceID = traceID
		l7TracingSpan.ResponseStatus = responseStatus
		l7TracingSpan.ServiceUname = serviceUname
		l7TracingSpan.OriginID = id
		l7TracingSpan.TapSide = tapSide
		result = append(result, l7TracingSpan)
	}
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
		if mergeFlow.VtapID != flow.VtapID || mergeFlow.TapPort != flow.TapPort || mergeFlow.TapPortType != flow.TapPortType || mergeFlow.L7Protocol != flow.L7Protocol || *mergeFlow.RequestID != *flow.RequestID || mergeFlow.TapSide != flow.TapSide || mergeFlow.FlowID != flow.FlowID {
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
			// 系统span syscall_cap_seq判断合并
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
