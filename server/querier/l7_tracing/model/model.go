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

package model

import "context"

type L7Tracing struct {
	ID           uint64 `json:"_id"`
	Database     string `json:"database"`
	Table        string `json:"table"`
	MaxIteration int    `json:"max_iteration"`
	TimeStart    int    `json:"time_start" binding:"required"`
	TimeEnd      int    `json:"time_end" binding:"required"`
	Debug        bool   `json:"debug"`
	Context      context.Context
}

type L7TracingSpan struct {
	IDs                    []uint64 `json:"_ids"`
	RelatedIds             []string `json:"related_ids"`
	StartTimeUs            int      `json:"start_time_us"`
	EndTimeUs              int      `json:"end_time_us"`
	Duration               int      `json:"duration"`
	SelfTime               int      `json:"selftime"`
	TapSide                string   `json:"tap_side"`
	EnumTapSide            string   `json:"Enum(tap_side)"`
	L7Protocol             int      `json:"l7_protocol"`
	L7ProtocolStr          string   `json:"l7_protocol_str"`
	Endpoint               string   `json:"endpoint"`
	RequestType            string   `json:"request_type"`
	RequestResource        string   `json:"request_resource"`
	ResponseStatus         int      `json:"response_status"`
	FlowID                 uint64   `json:"flow_id"`
	RequestID              *uint64  `json:"request_id"`
	XRequestID0            string   `json:"x_request_id_0"`
	XRequestID1            string   `json:"x_request_id_1"`
	TraceID                string   `json:"trace_id"`
	SpanID                 string   `json:"span_id"`
	ParentSpanID           string   `json:"parent_span_id"`
	ReqTcpSeq              int      `json:"req_tcp_seq"`
	RespTcpSeq             int      `json:"resp_tcp_seq"`
	SyscallTraceIDRequest  uint64   `json:"syscall_trace_id_request"`
	SyscallTraceIDResponse uint64   `json:"syscall_trace_id_response"`
	SyscallCapSeq0         int      `json:"syscall_cap_seq_0"`
	SyscallCapSeq1         int      `json:"syscall_cap_seq_1"`
	Attribute              string   `json:"attribute"`
	ID                     int      `json:"id"`
	ParentID               int      `json:"parent_id"`
	Childs                 []int    `json:"childs"`
	ProcessID              int      `json:"process_id"`
	VtapID                 int      `json:"vtap_id"`
	ServiceUID             string   `json:"service_uid"`
	ServiceUname           string   `json:"service_uname"`
	AppService             string   `json:"app_service"`
	AppInstance            string   `json:"app_instance"`
	TapPort                string   `json:"tap_port"`
	TapPortName            string   `json:"tap_port_name"`
	ResourceFromVtap       string   `json:"resource_from_vtap"`
	SetParentInfo          string   `json:"set_parent_info"`
	AutoInstance           string   `json:"auto_instance"`
	TapID                  int      `json:"tap_id"`
	Tap                    string   `json:"tap"`
	Subnet                 string   `json:"subnet"`
	IP                     string   `json:"ip"`
	AutoService            string   `json:"auto_service"`
	AutoServiceID          string   `json:"auto_service_id"`
	ProcessKname           string   `json:"process_kname"`
	DeepflowSpanID         string   `json:"deepflow_span_id"`
	DeepflowParentSpanID   string   `json:"deepflow_parent_span_id"`
}

type Debug struct {
	IP        string `json:"ip"`
	Sql       string `json:"sql"`
	SqlCH     string `json:"sql_CH"`
	QueryTime string `json:"query_time"`
	QueryUUID string `json:"query_uuid"`
	Error     string `json:"error"`
}

type L7TracingDebug struct {
	QuerierDebug []Debug `json:"querier_debug"`
	FormatTime   string  `json:"format_time"`
}
