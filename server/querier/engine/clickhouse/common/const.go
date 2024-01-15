/*
 * Copyright (c) 2024 Yunshan Networks
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

const PERMISSION_TYPE_NUM = 3
const DB_NAME_FLOW_LOG = "flow_log"
const DB_NAME_FLOW_METRICS = "flow_metrics"
const DB_NAME_EXT_METRICS = "ext_metrics"
const DB_NAME_DEEPFLOW_SYSTEM = "deepflow_system"
const DB_NAME_EVENT = "event"
const DB_NAME_PROFILE = "profile"
const DB_NAME_PROMETHEUS = "prometheus"
const DB_NAME_FLOW_TAG = "flow_tag"
const IndexTypeIncremetalId = "incremental-id"
const FormatHex = "hex"
const TagServerChPrefix = "服务端"
const TagClientChPrefix = "客户端"
const TagServerEnPrefix = "Server"
const TagClientEnPrefix = "Client"

var DB_TABLE_MAP = map[string][]string{
	DB_NAME_FLOW_LOG:        []string{"l4_flow_log", "l7_flow_log", "l4_packet", "l7_packet"},
	DB_NAME_FLOW_METRICS:    []string{"vtap_flow_port", "vtap_flow_edge_port", "vtap_app_port", "vtap_app_edge_port", "vtap_acl"},
	DB_NAME_EXT_METRICS:     []string{"ext_common"},
	DB_NAME_DEEPFLOW_SYSTEM: []string{"deepflow_system_common"},
	DB_NAME_EVENT:           []string{"event", "perf_event", "alarm_event"},
	DB_NAME_PROFILE:         []string{"in_process"},
	DB_NAME_PROMETHEUS:      []string{"samples"},
}

var SHOW_TAG_VALUE_MAP = map[string][]string{
	"ip_resource_map": []string{"ip", "subnet", "region", "az", "host", "chost", "l3_epc", "router", "dhcpgw", "lb", "lb_listener", "natgw", "redis", "rds", "pod_cluster", "pod_ns", "pod_node", "pod_ingress", "pod_service", "pod_group", "pod"},
	"pod_ns_map":      []string{"pod_ns", "pod_cluster"},
	"pod_group_map":   []string{"pod_group", "pod_cluster", "pod_ns"},
	"pod_service_map": []string{"pod_service", "pod_cluster", "pod_ns"},
	"pod_map":         []string{"pod", "pod_cluster", "pod_ns", "pod_node", "pod_service", "pod_group"},
	"chost_map":       []string{"chost", "host", "l3_epc"},
	"gprocess_map":    []string{"gprocess", "chost", "l3_epc"},
}
