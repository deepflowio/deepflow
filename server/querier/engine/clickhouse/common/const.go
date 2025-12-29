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
const DB_NAME_DEEPFLOW_SYSTEM = "deepflow_system" // Abandoned
const DB_NAME_DEEPFLOW_ADMIN = "deepflow_admin"
const DB_NAME_DEEPFLOW_TENANT = "deepflow_tenant"
const DB_NAME_EVENT = "event"
const DB_NAME_PROFILE = "profile"
const DB_NAME_PROMETHEUS = "prometheus"
const DB_NAME_FLOW_TAG = "flow_tag"
const DB_NAME_APPLICATION_LOG = "application_log"
const TABLE_NAME_VTAP_ACL = "traffic_policy"
const TABLE_NAME_TRACE_TREE = "trace_tree"
const TABLE_NAME_SPAN_WITH_TRACE_ID = "span_with_trace_id"
const TABLE_NAME_L7_FLOW_LOG = "l7_flow_log"
const TABLE_NAME_EVENT = "event"
const TABLE_NAME_FILE_EVENT = "file_event"
const TABLE_NAME_IN_PROCESS = "in_process"
const TABLE_NAME_IN_PROCESS_METRICS = "in_process_metrics"
const TABLE_NAME_FILE_EVENT_METRICS = "file_event_metrics"
const INDEX_TYPE_INCREMETAL_ID = "incremental-id"
const FORMAT_HEX = "hex"
const TAG_SERVER_CH_PREFIX = "服务端"
const TAG_CLIENT_CH_PREFIX = "客户端"
const TAG_SERVER_EN_PREFIX = "Server"
const TAG_CLIENT_EN_PREFIX = "Client"
const LANGUAGE_EN = "en"
const SUCCESS_RATIO_METRICS_NAME = "success_ratio"
const TRACE_ID_TAG = "trace_id"
const TRACE_IDS_TAG = "trace_ids"
const TRACE_ID_2_TAG = "_trace_id_2"

const (
	NATIVE_FIELD_TYPE_TAG            = 1
	NATIVE_FIELD_TYPE_METRIC         = 2
	NATIVE_FIELD_CATEGORY_CUSTOM_TAG = "Custom Tag"
	NATIVE_FIELD_CATEGORY_METRICS    = "metrics"
	NATIVE_FIELD_STATE_NORMAL        = 1
)

var DB_TABLE_MAP = map[string][]string{
	DB_NAME_FLOW_LOG:        []string{"l4_flow_log", "l7_flow_log", "l4_packet", "l7_packet"},
	DB_NAME_FLOW_METRICS:    []string{"network", "network_map", "application", "application_map", "traffic_policy"},
	DB_NAME_EXT_METRICS:     []string{"ext_common"},
	DB_NAME_DEEPFLOW_ADMIN:  []string{"deepflow_server"},
	DB_NAME_DEEPFLOW_TENANT: []string{"deepflow_collector"},
	DB_NAME_EVENT:           []string{"event", "file_event", "alert_event", TABLE_NAME_FILE_EVENT_METRICS},
	DB_NAME_PROFILE:         []string{"in_process", TABLE_NAME_IN_PROCESS_METRICS},
	DB_NAME_PROMETHEUS:      []string{"samples"},
	DB_NAME_APPLICATION_LOG: []string{"log"},
}

var SHOW_TAG_VALUE_MAP = map[string][]string{
	"pod_ns_map":      []string{"pod_ns", "pod_cluster"},
	"pod_group_map":   []string{"pod_group", "pod_cluster", "pod_ns"},
	"pod_service_map": []string{"pod_service", "pod_cluster", "pod_ns"},
	"pod_map":         []string{"pod", "pod_cluster", "pod_ns", "pod_node", "pod_service", "pod_group"},
	"chost_map":       []string{"chost", "host", "l3_epc", "chost_ip", "chost_hostname", "subnet"},
	"gprocess_map":    []string{"gprocess", "chost", "l3_epc"},
	"pod_ingress_map": []string{"pod_cluster", "pod_ns", "pod_ingress"},
	"pod_node_map":    []string{"pod_cluster", "pod_node"},
	"subnet_map":      []string{"l3_epc", "subnet"},
	"biz_service_map": []string{"biz_service.group"},
}

var InverseOperatorMap = map[string]string{
	"not match": "match",
	"not ilike": "ilike",
	"not in":    "in",
	"!=":        "=",
}

var PositiveOperatorMap = map[string]string{
	"match": "not match",
	"ilike": "not ilike",
	"in":    "not in",
	"=":     "!=",
}
