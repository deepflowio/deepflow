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

import (
	"context"
)

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
	OriginID               string         `json:"origin_id"`
	IDs                    []string       `json:"_ids"`
	RelatedIDs             []string       `json:"related_ids"`
	StartTimeUs            int            `json:"start_time_us"`
	EndTimeUs              int            `json:"end_time_us"`
	Duration               int            `json:"duration"`
	SelfTime               int            `json:"selftime"`
	TapSide                string         `json:"tap_side"`
	EnumTapSide            string         `json:"Enum(tap_side)"`
	L7Protocol             int            `json:"l7_protocol"`
	L7ProtocolStr          string         `json:"l7_protocol_str"`
	Endpoint               string         `json:"endpoint"`
	RequestType            string         `json:"request_type"`
	RequestResource        string         `json:"request_resource"`
	ResponseStatus         int            `json:"response_status"`
	FlowID                 string         `json:"flow_id"`
	RequestID              *uint64        `json:"request_id"`
	XRequestID0            string         `json:"x_request_id_0"`
	XRequestID1            string         `json:"x_request_id_1"`
	TraceID                string         `json:"trace_id"`
	SpanID                 string         `json:"span_id"`
	ParentSpanID           string         `json:"parent_span_id"`
	ReqTcpSeq              int            `json:"req_tcp_seq"`
	RespTcpSeq             int            `json:"resp_tcp_seq"`
	SyscallTraceIDRequest  string         `json:"syscall_trace_id_request"`
	SyscallTraceIDResponse string         `json:"syscall_trace_id_response"`
	SyscallCapSeq0         int            `json:"syscall_cap_seq_0"`
	SyscallCapSeq1         int            `json:"syscall_cap_seq_1"`
	Attribute              string         `json:"attribute"`
	ID                     int            `json:"id"`
	ParentID               int            `json:"parent_id"`
	Childs                 []int          `json:"childs"`
	ProcessID              int            `json:"process_id"`
	ProcessID0             int            `json:"process_id_0"`
	ProcessID1             int            `json:"process_id_1"`
	VtapID                 int            `json:"vtap_id"`
	Service                *TraceService  `json:"service"`
	ServiceUID             string         `json:"service_uid"`
	ServiceUname           string         `json:"service_uname"`
	AppService             string         `json:"app_service"`
	AppInstance            string         `json:"app_instance"`
	TapPort                string         `json:"tap_port"`
	TapPortType            int            `json:"tap_port_type"`
	TapPortName            string         `json:"tap_port_name"`
	ResourceFromVtap       string         `json:"resource_from_vtap"`
	SetParentInfo          string         `json:"set_parent_info"`
	AutoInstance           string         `json:"auto_instance"`
	AutoInstance0          string         `json:"auto_instance_0"`
	AutoInstance1          string         `json:"auto_instance_1"`
	TapID                  int            `json:"tap_id"`
	Tap                    string         `json:"tap"`
	Subnet                 string         `json:"subnet"`
	Subnet0                string         `json:"subnet_0"`
	Subnet1                string         `json:"subnet_1"`
	SubnetID               int            `json:"subnet_id"`
	SubnetID0              int            `json:"subnet_id_0"`
	SubnetID1              int            `json:"subnet_id_1"`
	IP                     string         `json:"ip"`
	IP0                    string         `json:"ip_0"`
	IP1                    string         `json:"ip_1"`
	AutoService            string         `json:"auto_service"`
	AutoService0           string         `json:"auto_service_0"`
	AutoService1           string         `json:"auto_service_1"`
	AutoServiceID          int            `json:"auto_service_id"`
	AutoServiceID0         int            `json:"auto_service_id_0"`
	AutoServiceID1         int            `json:"auto_service_id_1"`
	AutoServiceType        int            `json:"auto_service_type"`
	AutoServiceType0       int            `json:"auto_service_type_0"`
	AutoServiceType1       int            `json:"auto_service_type_1"`
	ProcessKname           string         `json:"process_kname"`
	ProcessKname0          string         `json:"process_kname_0"`
	ProcessKname1          string         `json:"process_kname_1"`
	DeepflowSpanID         string         `json:"deepflow_span_id"`
	DeepflowParentSpanID   string         `json:"deepflow_parent_span_id"`
	Type                   int            `json:"type"`
	HttpProxyClient        string         `json:"http_proxy_client"`
	Protocol               int            `json:"protocol"`
	Version                string         `json:"version"`
	UID                    int            `json:"_uid"`
	ParentAppFlow          *L7TracingSpan `json:"parent_app_flow"`
	ParentSyscallFlow      *L7TracingSpan `json:"parent_syscall_flow"`
	Network                *TraceNetwork  `json:"network"`
	NetworkFlow            *TraceNetwork  `json:"network_flow"`
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

type TraceService struct {
	VtapID    int
	ProcessID int

	DirectFlows          []*L7TracingSpan
	AppFlowOfDirectFlows []*L7TracingSpan
	UnattachedFlows      map[string][]*L7TracingSpan
	SubnetID             int
	Subnet               string
	IP                   string
	AutoServiceType      int
	AutoServiceID        int
	AutoService          string
	ProcessKname         string
	StartTimeUs          int
	EndTimeUs            int
	Level                int
}

type TraceNetwork struct {
	ReqTcpSeq       int
	RespTcpSeq      int
	SpanID          string
	HasSyscall      bool
	Meta            NetworkMeta
	Flows           []*L7TracingSpan
	StartTimeUs     int
	EndTimeUs       int
	XRequestID0     string
	XRequestID1     string
	HttpProxyClient string
	Protocol        int
	L7Protocol      int
	L7ProtocolStr   string
	Version         string
	TraceID         string
	Endpoint        string
}

type NetworkMeta struct {
	XRequestID0     string
	XRequestID1     string
	HttpProxyClient string
	Protocol        int
	L7Protocol      int
	L7ProtocolStr   string
	Version         string
	TraceID         string
	Endpoint        string
	SpanID          string
}
