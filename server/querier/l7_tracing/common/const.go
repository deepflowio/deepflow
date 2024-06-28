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

const (
	INVALID_POST_DATA = "INVALID_POST_DATA"
)

const (
	DATABASE_FLOW_LOG = "flow_log"
	TABLE_L7_FLOW_LOG = "l7_flow_log"
	MAX_ITERATION     = 30
	NTP_DELAY_US      = 10000
)

const (
	L7_FLOW_TYPE_REQUEST  = 0
	L7_FLOW_TYPE_RESPONSE = 1
	L7_FLOW_TYPE_SESSION  = 2
)

// tap_side
const (
	TAP_SIDE_UNKNOWN                   = ""
	TAP_SIDE_CLIENT_PROCESS            = "c-p"
	TAP_SIDE_CLIENT_NIC                = "c"
	TAP_SIDE_CLIENT_POD_NODE           = "c-nd"
	TAP_SIDE_CLIENT_HYPERVISOR         = "c-hv"
	TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR = "c-gw-hv"
	TAP_SIDE_CLIENT_GATEWAY            = "c-gw"
	TAP_SIDE_SERVER_GATEWAY            = "s-gw"
	TAP_SIDE_SERVER_GATEWAY_HAPERVISOR = "s-gw-hv"
	TAP_SIDE_SERVER_HYPERVISOR         = "s-hv"
	TAP_SIDE_SERVER_POD_NODE           = "s-nd"
	TAP_SIDE_SERVER_NIC                = "s"
	TAP_SIDE_SERVER_PROCESS            = "s-p"
	TAP_SIDE_REST                      = "rest"
	TAP_SIDE_LOCAL                     = "local"
	TAP_SIDE_APP                       = "app"
	TAP_SIDE_CLIENT_APP                = "c-app"
	TAP_SIDE_SERVER_APP                = "s-app"
)

var TAP_SIDE_RANKS = map[string]int{
	TAP_SIDE_CLIENT_PROCESS:            1,
	TAP_SIDE_CLIENT_NIC:                2,
	TAP_SIDE_CLIENT_POD_NODE:           3,
	TAP_SIDE_CLIENT_HYPERVISOR:         4,
	TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR: 5,
	TAP_SIDE_CLIENT_GATEWAY:            6,
	TAP_SIDE_SERVER_GATEWAY:            6, // 由于可能多次穿越网关区域，c-gw和s-gw还需要重排
	TAP_SIDE_SERVER_GATEWAY_HAPERVISOR: 8,
	TAP_SIDE_SERVER_HYPERVISOR:         9,
	TAP_SIDE_SERVER_POD_NODE:           10,
	TAP_SIDE_SERVER_NIC:                11,
	TAP_SIDE_SERVER_PROCESS:            12,
	TAP_SIDE_REST:                      13,
	TAP_SIDE_LOCAL:                     13, // rest和local需要就近排列到其他位置上
}

var RETURN_FIELDS = []string{
	// 追踪Meta信息
	"l7_protocol",
	"l7_protocol_str",
	"type",
	"req_tcp_seq",
	"resp_tcp_seq",
	"start_time_us",
	"end_time_us",
	"vtap_id",
	"tap_port",
	"tap_port_name",
	"tap_port_type",
	"resource_from_vtap",
	"syscall_trace_id_request",
	"syscall_trace_id_response",
	"syscall_cap_seq_0",
	"syscall_cap_seq_1",
	"trace_id",
	"span_id",
	"parent_span_id",
	"x_request_id_0",
	"x_request_id_1",
	"_id",
	"flow_id",
	"protocol",
	"version",
	// 资源信息
	"process_id_0",
	"process_id_1",
	"tap_side",
	"Enum(tap_side)",
	"subnet_id_0",
	"subnet_0",
	"ip_0",
	"auto_instance_type_0",
	"auto_instance_id_0",
	"auto_instance_0",
	"auto_instance_0_node_type",
	"auto_instance_0_icon_id",
	"process_kname_0",
	"subnet_id_1",
	"subnet_1",
	"ip_1",
	"app_service",
	"app_instance",
	"auto_instance_type_1",
	"auto_instance_id_1",
	"auto_instance_1",
	"auto_instance_1_node_type",
	"auto_instance_1_icon_id",
	"process_kname_1",
	"auto_service_type_0",
	"auto_service_id_0",
	"auto_service_0",
	"auto_service_type_1",
	"auto_service_id_1",
	"auto_service_1",
	"tap_id",
	"tap",
	// 指标信息
	"response_status",
	"response_duration",
	"response_code",
	"response_exception",
	"response_result",
	"request_type",
	"request_domain",
	"request_resource",
	"request_id",
	"http_proxy_client",
	"endpoint",
}
var FIELDS_MAP = map[string]string{
	"start_time_us":             "toUnixTimestamp64Micro(start_time) as start_time_us",
	"end_time_us":               "toUnixTimestamp64Micro(end_time) as end_time_us",
	"auto_instance_0_node_type": "node_type(auto_instance_0) as auto_instance_0_node_type",
	"auto_instance_0_icon_id":   "icon_id(auto_instance_0) as auto_instance_0_icon_id",
	"auto_instance_1_node_type": "node_type(auto_instance_1) as auto_instance_1_node_type",
	"auto_instance_1_icon_id":   "icon_id(auto_instance_1) as auto_instance_1_icon_id",
	"_id":                       "toString(_id) as `_id_str`",
}
