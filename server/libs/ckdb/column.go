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

package ckdb

import "fmt"

const MAX_APP_LABEL_COLUMN_INDEX = 256

var COLUMN_APP_LABEL_VALUE_IDs []string

func init() {
	COLUMN_APP_LABEL_VALUE_IDs = make([]string, MAX_APP_LABEL_COLUMN_INDEX+1)
	for i := range COLUMN_APP_LABEL_VALUE_IDs {
		COLUMN_APP_LABEL_VALUE_IDs[i] = fmt.Sprintf("app_label_value_id_%d", i)
	}
}

const (
	COLUMN_ACL_GID                    = "acl_gid"
	COLUMN_ACL_GIDS                   = "acl_gids"
	COLUMN_AGENT_ID                   = "agent_id"
	COLUMN_ALERT_POLICY               = "alert_policy"
	COLUMN_APP_INSTANCE               = "app_instance"
	COLUMN_APP_LABEL_VALUE_ID         = "app_label_value_id"
	COLUMN_APP_SERVICE                = "app_service"
	COLUMN_ART_COUNT                  = "art_count"
	COLUMN_ART_MAX                    = "art_max"
	COLUMN_ART_SUM                    = "art_sum"
	COLUMN_ATTRIBUTE_NAMES            = "attribute_names"
	COLUMN_ATTRIBUTE_VALUES           = "attribute_values"
	COLUMN_AUTO_INSTANCE_ID           = "auto_instance_id"
	COLUMN_AUTO_INSTANCE_ID_0         = "auto_instance_id_0"
	COLUMN_AUTO_INSTANCE_ID_1         = "auto_instance_id_1"
	COLUMN_AUTO_INSTANCE_TYPE         = "auto_instance_type"
	COLUMN_AUTO_INSTANCE_TYPE_0       = "auto_instance_type_0"
	COLUMN_AUTO_INSTANCE_TYPE_1       = "auto_instance_type_1"
	COLUMN_AUTO_SERVICE_ID            = "auto_service_id"
	COLUMN_AUTO_SERVICE_ID_0          = "auto_service_id_0"
	COLUMN_AUTO_SERVICE_ID_1          = "auto_service_id_1"
	COLUMN_AUTO_SERVICE_TYPE          = "auto_service_type"
	COLUMN_AUTO_SERVICE_TYPE_0        = "auto_service_type_0"
	COLUMN_AUTO_SERVICE_TYPE_1        = "auto_service_type_1"
	COLUMN_AZ_ID                      = "az_id"
	COLUMN_AZ_ID_0                    = "az_id_0"
	COLUMN_AZ_ID_1                    = "az_id_1"
	COLUMN_BIZ_TYPE                   = "biz_type"
	COLUMN_BIZ_CODE                   = "biz_code"
	COLUMN_BIZ_SCENARIO               = "biz_scenario"
	COLUMN_BODY                       = "body"
	COLUMN_BYTE                       = "byte"
	COLUMN_BYTES                      = "bytes"
	COLUMN_BYTE_RX                    = "byte_rx"
	COLUMN_BYTE_TX                    = "byte_tx"
	COLUMN_CAPTURED_REQUEST_BYTE      = "captured_request_byte"
	COLUMN_CAPTURED_RESPONSE_BYTE     = "captured_response_byte"
	COLUMN_CAPTURE_NETWORK_TYPE_ID    = "capture_network_type_id"
	COLUMN_CAPTURE_NIC                = "capture_nic"
	COLUMN_CAPTURE_NIC_TYPE           = "capture_nic_type"
	COLUMN_CIT_COUNT                  = "cit_count"
	COLUMN_CIT_MAX                    = "cit_max"
	COLUMN_CIT_SUM                    = "cit_sum"
	COLUMN_CLIENT_ACK_MISS            = "client_ack_miss"
	COLUMN_CLIENT_ERROR               = "client_error"
	COLUMN_CLIENT_ESTABLISH_FAIL      = "client_establish_fail"
	COLUMN_CLIENT_ESTABLISH_OTHER_RST = "client_establish_other_rst"
	COLUMN_CLIENT_HALF_CLOSE_FLOW     = "client_half_close_flow"
	COLUMN_CLIENT_PORT                = "client_port"
	COLUMN_CLIENT_RST_FLOW            = "client_rst_flow"
	COLUMN_CLIENT_SOURCE_PORT_REUSE   = "client_source_port_reuse"
	COLUMN_CLOSED_FLOW                = "closed_flow"
	COLUMN_CLOSE_TYPE                 = "close_type"
	COLUMN_COMPRESSION_ALGO           = "compression_algo"
	COLUMN_COUNT                      = "count"
	COLUMN_DIRECTION_SCORE            = "direction_score"
	COLUMN_DURATION                   = "duration"
	COLUMN_ENCODED_SPAN               = "encoded_span"
	COLUMN_ENCODED_SPAN_LIST          = "encoded_span_list"
	COLUMN_ENDPOINT                   = "endpoint"
	COLUMN_END_TIME                   = "end_time"
	COLUMN_EPC_ID_0                   = "epc_id_0"
	COLUMN_EPC_ID_1                   = "epc_id_1"
	COLUMN_ERROR                      = "error"
	COLUMN_ETH_TYPE                   = "eth_type"
	COLUMN_EVENTS                     = "events"
	COLUMN_EVENT_DESC                 = "event_desc"
	COLUMN_EVENT_LEVEL                = "event_level"
	COLUMN_EVENT_TYPE                 = "event_type"
	COLUMN_FIELD_NAME                 = "field_name"
	COLUMN_FIELD_TYPE                 = "field_type"
	COLUMN_FIELD_VALUE                = "field_value"
	COLUMN_FIELD_VALUE_TYPE           = "field_value_type"
	COLUMN_FILE_DIR                   = "file_dir"
	COLUMN_FILE_NAME                  = "file_name"
	COLUMN_FILE_TYPE                  = "file_type"
	COLUMN_FIN_COUNT                  = "fin_count"
	COLUMN_FLOW_ID                    = "flow_id"
	COLUMN_AGGREGATED_FLOW_IDS        = "aggregated_flow_ids"
	COLUMN_FLOW_LOAD                  = "flow_load"
	COLUMN_GPROCESS_ID                = "gprocess_id"
	COLUMN_GPROCESS_ID_0              = "gprocess_id_0"
	COLUMN_GPROCESS_ID_1              = "gprocess_id_1"
	COLUMN_HOST_ID                    = "host_id"
	COLUMN_HOST_ID_0                  = "host_id_0"
	COLUMN_HOST_ID_1                  = "host_id_1"
	COLUMN_HTTP_PROXY_CLIENT          = "http_proxy_client"
	COLUMN_ID                         = "id"
	COLUMN_INIT_IPID                  = "init_ipid"
	COLUMN_IP4                        = "ip4"
	COLUMN_IP4_0                      = "ip4_0"
	COLUMN_IP4_1                      = "ip4_1"
	COLUMN_IP6                        = "ip6"
	COLUMN_IP6_0                      = "ip6_0"
	COLUMN_IP6_1                      = "ip6_1"
	COLUMN_IS_IPV4                    = "is_ipv4"
	COLUMN_IS_KEY_SERVICE             = "is_key_service"
	COLUMN_IS_NEW_FLOW                = "is_new_flow"
	COLUMN_IS_TLS                     = "is_tls"
	COLUMN_IS_ASYNC                   = "is_async"
	COLUMN_IS_REVERSED                = "is_reversed"
	COLUMN_L2_END_0                   = "l2_end_0"
	COLUMN_L2_END_1                   = "l2_end_1"
	COLUMN_L3_BYTE_RX                 = "l3_byte_rx"
	COLUMN_L3_BYTE_TX                 = "l3_byte_tx"
	COLUMN_L3_DEVICE_ID               = "l3_device_id"
	COLUMN_L3_DEVICE_ID_0             = "l3_device_id_0"
	COLUMN_L3_DEVICE_ID_1             = "l3_device_id_1"
	COLUMN_L3_DEVICE_TYPE             = "l3_device_type"
	COLUMN_L3_DEVICE_TYPE_0           = "l3_device_type_0"
	COLUMN_L3_DEVICE_TYPE_1           = "l3_device_type_1"
	COLUMN_L3_END_0                   = "l3_end_0"
	COLUMN_L3_END_1                   = "l3_end_1"
	COLUMN_L3_EPC_ID                  = "l3_epc_id"
	COLUMN_L3_EPC_ID_0                = "l3_epc_id_0"
	COLUMN_L3_EPC_ID_1                = "l3_epc_id_1"
	COLUMN_L4_BYTE_RX                 = "l4_byte_rx"
	COLUMN_L4_BYTE_TX                 = "l4_byte_tx"
	COLUMN_L7_CLIENT_ERROR            = "l7_client_error"
	COLUMN_L7_ERROR                   = "l7_error"
	COLUMN_L7_PARSE_FAILED            = "l7_parse_failed"
	COLUMN_L7_PROTOCOL                = "l7_protocol"
	COLUMN_L7_PROTOCOL_STR            = "l7_protocol_str"
	COLUMN_L7_REQUEST                 = "l7_request"
	COLUMN_L7_RESPONSE                = "l7_response"
	COLUMN_L7_SERVER_ERROR            = "l7_server_error"
	COLUMN_L7_SERVER_TIMEOUT          = "l7_server_timeout"
	COLUMN_L7_TIMEOUT                 = "l7_timeout"
	COLUMN_LAST_KEEPALIVE_ACK         = "last_keepalive_ack"
	COLUMN_LAST_KEEPALIVE_SEQ         = "last_keepalive_seq"
	COLUMN_MAC_0                      = "mac_0"
	COLUMN_MAC_1                      = "mac_1"
	COLUMN_METRICS_FLOAT_NAMES        = "metrics_float_names"
	COLUMN_METRICS_FLOAT_VALUES       = "metrics_float_values"
	COLUMN_METRICS_NAMES              = "metrics_names"
	COLUMN_METRICS_VALUES             = "metrics_values"
	COLUMN_METRIC_ID                  = "metric_id"
	COLUMN_METRIC_UNIT                = "metric_unit"
	COLUMN_METRIC_VALUE               = "metric_value"
	COLUMN_METRIC_VALUE_STR           = "metric_value_str"
	COLUMN_MOUNT_SOURCE               = "mount_source"
	COLUMN_MOUNT_POINT                = "mount_point"
	COLUMN_NAT_REAL_IP4_0             = "nat_real_ip4_0"
	COLUMN_NAT_REAL_IP4_1             = "nat_real_ip4_1"
	COLUMN_NAT_REAL_PORT_0            = "nat_real_port_0"
	COLUMN_NAT_REAL_PORT_1            = "nat_real_port_1"
	COLUMN_NAT_SOURCE                 = "nat_source"
	COLUMN_NEW_FLOW                   = "new_flow"
	COLUMN_OBSERVATION_POINT          = "observation_point"
	COLUMN_OFFSET                     = "offset"
	COLUMN_OOO_TX                     = "ooo_tx"
	COLUMN_OOO_RX                     = "ooo_rx"
	COLUMN_PACKET                     = "packet"
	COLUMN_PACKET_BATCH               = "packet_batch"
	COLUMN_PACKET_COUNT               = "packet_count"
	COLUMN_PACKET_RX                  = "packet_rx"
	COLUMN_PACKET_TX                  = "packet_tx"
	COLUMN_PARENT_SPAN_ID             = "parent_span_id"
	COLUMN_POD_CLUSTER_ID             = "pod_cluster_id"
	COLUMN_POD_CLUSTER_ID_0           = "pod_cluster_id_0"
	COLUMN_POD_CLUSTER_ID_1           = "pod_cluster_id_1"
	COLUMN_POD_GROUP_ID               = "pod_group_id"
	COLUMN_POD_GROUP_ID_0             = "pod_group_id_0"
	COLUMN_POD_GROUP_ID_1             = "pod_group_id_1"
	COLUMN_POD_ID                     = "pod_id"
	COLUMN_POD_ID_0                   = "pod_id_0"
	COLUMN_POD_ID_1                   = "pod_id_1"
	COLUMN_POD_NODE_ID                = "pod_node_id"
	COLUMN_POD_NODE_ID_0              = "pod_node_id_0"
	COLUMN_POD_NODE_ID_1              = "pod_node_id_1"
	COLUMN_POD_NS_ID                  = "pod_ns_id"
	COLUMN_POD_NS_ID_0                = "pod_ns_id_0"
	COLUMN_POD_NS_ID_1                = "pod_ns_id_1"
	COLUMN_POLICY_ID                  = "policy_id"
	COLUMN_POLICY_TYPE                = "policy_type"
	COLUMN_PROCESS_ID                 = "process_id"
	COLUMN_PROCESS_ID_0               = "process_id_0"
	COLUMN_PROCESS_ID_1               = "process_id_1"
	COLUMN_PROCESS_KNAME              = "process_kname"
	COLUMN_PROCESS_KNAME_0            = "process_kname_0"
	COLUMN_PROCESS_KNAME_1            = "process_kname_1"
	COLUMN_PROCESS_START_TIME         = "process_start_time"
	COLUMN_PROFILE_CREATE_TIMESTAMP   = "profile_create_timestamp"
	COLUMN_PROFILE_EVENT_TYPE         = "profile_event_type"
	COLUMN_PROFILE_ID                 = "profile_id"
	COLUMN_PROFILE_IN_TIMESTAMP       = "profile_in_timestamp"
	COLUMN_PROFILE_LANGUAGE_TYPE      = "profile_language_type"
	COLUMN_PROFILE_LOCATION_STR       = "profile_location_str"
	COLUMN_PROFILE_VALUE              = "profile_value"
	COLUMN_PROFILE_VALUE_UNIT         = "profile_value_unit"
	COLUMN_PROTOCOL                   = "protocol"
	COLUMN_PROVINCE_0                 = "province_0"
	COLUMN_PROVINCE_1                 = "province_1"
	COLUMN_REGION_ID                  = "region_id"
	COLUMN_REGION_ID_0                = "region_id_0"
	COLUMN_REGION_ID_1                = "region_id_1"
	COLUMN_REQUEST                    = "request"
	COLUMN_REQUEST_DOMAIN             = "request_domain"
	COLUMN_REQUEST_ID                 = "request_id"
	COLUMN_REQUEST_LENGTH             = "request_length"
	COLUMN_REQUEST_RESOURCE           = "request_resource"
	COLUMN_REQUEST_TYPE               = "request_type"
	COLUMN_REQ_TCP_SEQ                = "req_tcp_seq"
	COLUMN_RESPONSE                   = "response"
	COLUMN_RESPONSE_CODE              = "response_code"
	COLUMN_RESPONSE_DURATION          = "response_duration"
	COLUMN_RESPONSE_EXCEPTION         = "response_exception"
	COLUMN_RESPONSE_LENGTH            = "response_length"
	COLUMN_RESPONSE_RESULT            = "response_result"
	COLUMN_RESPONSE_STATUS            = "response_status"
	COLUMN_RESP_TCP_SEQ               = "resp_tcp_seq"
	COLUMN_RETRANS                    = "retrans"
	COLUMN_RETRANS_RX                 = "retrans_rx"
	COLUMN_RETRANS_SYN                = "retrans_syn"
	COLUMN_RETRANS_SYNACK             = "retrans_synack"
	COLUMN_RETRANS_TX                 = "retrans_tx"
	COLUMN_ROLE                       = "role"
	COLUMN_RRT_COUNT                  = "rrt_count"
	COLUMN_RRT_MAX                    = "rrt_max"
	COLUMN_RRT_SUM                    = "rrt_sum"
	COLUMN_RTT                        = "rtt"
	COLUMN_RTT_CLIENT                 = "rtt_client"
	COLUMN_RTT_CLIENT_COUNT           = "rtt_client_count"
	COLUMN_RTT_CLIENT_MAX             = "rtt_client_max"
	COLUMN_RTT_CLIENT_SUM             = "rtt_client_sum"
	COLUMN_RTT_COUNT                  = "rtt_count"
	COLUMN_RTT_MAX                    = "rtt_max"
	COLUMN_RTT_SERVER                 = "rtt_server"
	COLUMN_RTT_SERVER_COUNT           = "rtt_server_count"
	COLUMN_RTT_SERVER_MAX             = "rtt_server_max"
	COLUMN_RTT_SERVER_SUM             = "rtt_server_sum"
	COLUMN_RTT_SUM                    = "rtt_sum"
	COLUMN_SEARCH_INDEX               = "search_index"
	COLUMN_SERVER_ERROR               = "server_error"
	COLUMN_SERVER_ESTABLISH_FAIL      = "server_establish_fail"
	COLUMN_SERVER_ESTABLISH_OTHER_RST = "server_establish_other_rst"
	COLUMN_SERVER_HALF_CLOSE_FLOW     = "server_half_close_flow"
	COLUMN_SERVER_PORT                = "server_port"
	COLUMN_SERVER_QUEUE_LACK          = "server_queue_lack"
	COLUMN_SERVER_RESET               = "server_reset"
	COLUMN_SERVER_RST_FLOW            = "server_rst_flow"
	COLUMN_SERVER_SYN_MISS            = "server_syn_miss"
	COLUMN_SERVICE_ID                 = "service_id"
	COLUMN_SERVICE_ID_0               = "service_id_0"
	COLUMN_SERVICE_ID_1               = "service_id_1"
	COLUMN_SEVERITY_NUMBER            = "severity_number"
	COLUMN_SIGNAL_SOURCE              = "signal_source"
	COLUMN_SPAN_ID                    = "span_id"
	COLUMN_SPAN_KIND                  = "span_kind"
	COLUMN_SPAN_NAME                  = "span_name"
	COLUMN_SQL_AFFECTED_ROWS          = "sql_affected_rows"
	COLUMN_SRT_COUNT                  = "srt_count"
	COLUMN_SRT_MAX                    = "srt_max"
	COLUMN_SRT_SUM                    = "srt_sum"
	COLUMN_START_TIME                 = "start_time"
	COLUMN_STATUS                     = "status"
	COLUMN_SUBNET_ID                  = "subnet_id"
	COLUMN_SUBNET_ID_0                = "subnet_id_0"
	COLUMN_SUBNET_ID_1                = "subnet_id_1"
	COLUMN_SYNACK_COUNT               = "synack_count"
	COLUMN_SYN_ACK_SEQ                = "syn_ack_seq"
	COLUMN_SYN_COUNT                  = "syn_count"
	COLUMN_SYN_SEQ                    = "syn_seq"
	COLUMN_SYSCALL_CAP_SEQ_0          = "syscall_cap_seq_0"
	COLUMN_SYSCALL_CAP_SEQ_1          = "syscall_cap_seq_1"
	COLUMN_SYSCALL_COROUTINE          = "syscall_coroutine"
	COLUMN_SYSCALL_COROUTINE_0        = "syscall_coroutine_0"
	COLUMN_SYSCALL_COROUTINE_1        = "syscall_coroutine_1"
	COLUMN_SYSCALL_THREAD             = "syscall_thread"
	COLUMN_SYSCALL_THREAD_0           = "syscall_thread_0"
	COLUMN_SYSCALL_THREAD_1           = "syscall_thread_1"
	COLUMN_SYSCALL_TRACE_ID_REQUEST   = "syscall_trace_id_request"
	COLUMN_SYSCALL_TRACE_ID_RESPONSE  = "syscall_trace_id_response"
	COLUMN_TABLE                      = "table"
	COLUMN_TAGGED                     = "tagged"
	COLUMN_TAG_INT_NAMES              = "tag_int_names"
	COLUMN_TAG_INT_VALUES             = "tag_int_values"
	COLUMN_TAG_NAMES                  = "tag_names"
	COLUMN_TAG_SOURCE                 = "tag_source"
	COLUMN_TAG_SOURCE_0               = "tag_source_0"
	COLUMN_TAG_SOURCE_1               = "tag_source_1"
	COLUMN_TAG_STRING_NAMES           = "tag_string_names"
	COLUMN_TAG_STRING_VALUES          = "tag_string_values"
	COLUMN_TAG_VALUES                 = "tag_values"
	COLUMN_TARGET_ID                  = "target_id"
	COLUMN_TARGET_TAGS                = "target_tags"
	COLUMN_TCP_ESTABLISH_FAIL         = "tcp_establish_fail"
	COLUMN_TCP_FLAGS_BIT_0            = "tcp_flags_bit_0"
	COLUMN_TCP_FLAGS_BIT_1            = "tcp_flags_bit_1"
	COLUMN_TCP_RST_FAIL               = "tcp_rst_fail"
	COLUMN_TCP_TIMEOUT                = "tcp_timeout"
	COLUMN_TCP_TRANSFER_FAIL          = "tcp_transfer_fail"
	COLUMN_TEAM_ID                    = "team_id"
	COLUMN_TIME                       = "time"
	COLUMN_TIMEOUT                    = "timeout"
	COLUMN_TIMESTAMP                  = "timestamp"
	COLUMN_TLS_RTT                    = "tls_rtt"
	COLUMN_TOTAL_BYTE_RX              = "total_byte_rx"
	COLUMN_TOTAL_BYTE_TX              = "total_byte_tx"
	COLUMN_TOTAL_PACKET_RX            = "total_packet_rx"
	COLUMN_TOTAL_PACKET_TX            = "total_packet_tx"
	COLUMN_TRACE_FLAGS                = "trace_flags"
	COLUMN_TRACE_ID                   = "trace_id"
	COLUMN_TRACE_ID_2                 = "_trace_id_2"
	COLUMN_TRACE_ID_INDEX             = "trace_id_index"
	COLUMN_TRIGGER_THRESHOLD          = "trigger_threshold"
	COLUMN_TUNNEL_IP_ID               = "tunnel_ip_id"
	COLUMN_TUNNEL_IS_IPV4             = "tunnel_is_ipv4"
	COLUMN_TUNNEL_RX_ID               = "tunnel_rx_id"
	COLUMN_TUNNEL_RX_IP4_0            = "tunnel_rx_ip4_0"
	COLUMN_TUNNEL_RX_IP4_1            = "tunnel_rx_ip4_1"
	COLUMN_TUNNEL_RX_IP6_0            = "tunnel_rx_ip6_0"
	COLUMN_TUNNEL_RX_IP6_1            = "tunnel_rx_ip6_1"
	COLUMN_TUNNEL_RX_MAC_0            = "tunnel_rx_mac_0"
	COLUMN_TUNNEL_RX_MAC_1            = "tunnel_rx_mac_1"
	COLUMN_TUNNEL_TIER                = "tunnel_tier"
	COLUMN_TUNNEL_TX_ID               = "tunnel_tx_id"
	COLUMN_TUNNEL_TX_IP4_0            = "tunnel_tx_ip4_0"
	COLUMN_TUNNEL_TX_IP4_1            = "tunnel_tx_ip4_1"
	COLUMN_TUNNEL_TX_IP6_0            = "tunnel_tx_ip6_0"
	COLUMN_TUNNEL_TX_IP6_1            = "tunnel_tx_ip6_1"
	COLUMN_TUNNEL_TX_MAC_0            = "tunnel_tx_mac_0"
	COLUMN_TUNNEL_TX_MAC_1            = "tunnel_tx_mac_1"
	COLUMN_TUNNEL_TYPE                = "tunnel_type"
	COLUMN_TYPE                       = "type"
	COLUMN_USER_ID                    = "user_id"
	COLUMN_VALUE                      = "value"
	COLUMN_VERSION                    = "version"
	COLUMN_VIRTUAL_TABLE_NAME         = "virtual_table_name"
	COLUMN_VLAN                       = "vlan"
	COLUMN_VPC_ID                     = "vpc_id"
	COLUMN_X_REQUEST_ID_0             = "x_request_id_0"
	COLUMN_X_REQUEST_ID_1             = "x_request_id_1"
	COLUMN_ZERO_WIN                   = "zero_win"
	COLUMN_ZERO_WIN_RX                = "zero_win_rx"
	COLUMN_ZERO_WIN_TX                = "zero_win_tx"
	COLUMN__ID                        = "_id"
	COLUMN__QUERY_REGION              = "_query_region"
	COLUMN__TARGET_UID                = "_target_uid"
	COLUMN__TID                       = "_tid"
	COLUMN__TYPE                      = "_type"
)

// can be generated from the above const by vim command:356,676s/\s*=\s*".*"\s*/,/g
var ColumnNames = []string{
	COLUMN_ACL_GID,
	COLUMN_ACL_GIDS,
	COLUMN_AGENT_ID,
	COLUMN_ALERT_POLICY,
	COLUMN_APP_INSTANCE,
	COLUMN_APP_LABEL_VALUE_ID,
	COLUMN_APP_SERVICE,
	COLUMN_ART_COUNT,
	COLUMN_ART_MAX,
	COLUMN_ART_SUM,
	COLUMN_ATTRIBUTE_NAMES,
	COLUMN_ATTRIBUTE_VALUES,
	COLUMN_AUTO_INSTANCE_ID,
	COLUMN_AUTO_INSTANCE_ID_0,
	COLUMN_AUTO_INSTANCE_ID_1,
	COLUMN_AUTO_INSTANCE_TYPE,
	COLUMN_AUTO_INSTANCE_TYPE_0,
	COLUMN_AUTO_INSTANCE_TYPE_1,
	COLUMN_AUTO_SERVICE_ID,
	COLUMN_AUTO_SERVICE_ID_0,
	COLUMN_AUTO_SERVICE_ID_1,
	COLUMN_AUTO_SERVICE_TYPE,
	COLUMN_AUTO_SERVICE_TYPE_0,
	COLUMN_AUTO_SERVICE_TYPE_1,
	COLUMN_AZ_ID,
	COLUMN_AZ_ID_0,
	COLUMN_AZ_ID_1,
	COLUMN_BIZ_TYPE,
	COLUMN_BIZ_CODE,
	COLUMN_BIZ_SCENARIO,
	COLUMN_BODY,
	COLUMN_BYTE,
	COLUMN_BYTES,
	COLUMN_BYTE_RX,
	COLUMN_BYTE_TX,
	COLUMN_CAPTURED_REQUEST_BYTE,
	COLUMN_CAPTURED_RESPONSE_BYTE,
	COLUMN_CAPTURE_NETWORK_TYPE_ID,
	COLUMN_CAPTURE_NIC,
	COLUMN_CAPTURE_NIC_TYPE,
	COLUMN_CIT_COUNT,
	COLUMN_CIT_MAX,
	COLUMN_CIT_SUM,
	COLUMN_CLIENT_ACK_MISS,
	COLUMN_CLIENT_ERROR,
	COLUMN_CLIENT_ESTABLISH_FAIL,
	COLUMN_CLIENT_ESTABLISH_OTHER_RST,
	COLUMN_CLIENT_HALF_CLOSE_FLOW,
	COLUMN_CLIENT_PORT,
	COLUMN_CLIENT_RST_FLOW,
	COLUMN_CLIENT_SOURCE_PORT_REUSE,
	COLUMN_CLOSED_FLOW,
	COLUMN_CLOSE_TYPE,
	COLUMN_COMPRESSION_ALGO,
	COLUMN_COUNT,
	COLUMN_DIRECTION_SCORE,
	COLUMN_DURATION,
	COLUMN_ENCODED_SPAN,
	COLUMN_ENCODED_SPAN_LIST,
	COLUMN_ENDPOINT,
	COLUMN_END_TIME,
	COLUMN_EPC_ID_0,
	COLUMN_EPC_ID_1,
	COLUMN_ERROR,
	COLUMN_ETH_TYPE,
	COLUMN_EVENTS,
	COLUMN_EVENT_DESC,
	COLUMN_EVENT_LEVEL,
	COLUMN_EVENT_TYPE,
	COLUMN_FIELD_NAME,
	COLUMN_FIELD_TYPE,
	COLUMN_FIELD_VALUE,
	COLUMN_FIELD_VALUE_TYPE,
	COLUMN_FILE_DIR,
	COLUMN_FILE_NAME,
	COLUMN_FILE_TYPE,
	COLUMN_FIN_COUNT,
	COLUMN_FLOW_ID,
	COLUMN_AGGREGATED_FLOW_IDS,
	COLUMN_FLOW_LOAD,
	COLUMN_GPROCESS_ID,
	COLUMN_GPROCESS_ID_0,
	COLUMN_GPROCESS_ID_1,
	COLUMN_HOST_ID,
	COLUMN_HOST_ID_0,
	COLUMN_HOST_ID_1,
	COLUMN_HTTP_PROXY_CLIENT,
	COLUMN_ID,
	COLUMN_INIT_IPID,
	COLUMN_IP4,
	COLUMN_IP4_0,
	COLUMN_IP4_1,
	COLUMN_IP6,
	COLUMN_IP6_0,
	COLUMN_IP6_1,
	COLUMN_IS_IPV4,
	COLUMN_IS_KEY_SERVICE,
	COLUMN_IS_NEW_FLOW,
	COLUMN_IS_TLS,
	COLUMN_IS_ASYNC,
	COLUMN_IS_REVERSED,
	COLUMN_L2_END_0,
	COLUMN_L2_END_1,
	COLUMN_L3_BYTE_RX,
	COLUMN_L3_BYTE_TX,
	COLUMN_L3_DEVICE_ID,
	COLUMN_L3_DEVICE_ID_0,
	COLUMN_L3_DEVICE_ID_1,
	COLUMN_L3_DEVICE_TYPE,
	COLUMN_L3_DEVICE_TYPE_0,
	COLUMN_L3_DEVICE_TYPE_1,
	COLUMN_L3_END_0,
	COLUMN_L3_END_1,
	COLUMN_L3_EPC_ID,
	COLUMN_L3_EPC_ID_0,
	COLUMN_L3_EPC_ID_1,
	COLUMN_L4_BYTE_RX,
	COLUMN_L4_BYTE_TX,
	COLUMN_L7_CLIENT_ERROR,
	COLUMN_L7_ERROR,
	COLUMN_L7_PARSE_FAILED,
	COLUMN_L7_PROTOCOL,
	COLUMN_L7_PROTOCOL_STR,
	COLUMN_L7_REQUEST,
	COLUMN_L7_RESPONSE,
	COLUMN_L7_SERVER_ERROR,
	COLUMN_L7_SERVER_TIMEOUT,
	COLUMN_L7_TIMEOUT,
	COLUMN_LAST_KEEPALIVE_ACK,
	COLUMN_LAST_KEEPALIVE_SEQ,
	COLUMN_MAC_0,
	COLUMN_MAC_1,
	COLUMN_METRICS_FLOAT_NAMES,
	COLUMN_METRICS_FLOAT_VALUES,
	COLUMN_METRICS_NAMES,
	COLUMN_METRICS_VALUES,
	COLUMN_METRIC_ID,
	COLUMN_METRIC_UNIT,
	COLUMN_METRIC_VALUE,
	COLUMN_METRIC_VALUE_STR,
	COLUMN_MOUNT_SOURCE,
	COLUMN_MOUNT_POINT,
	COLUMN_NAT_REAL_IP4_0,
	COLUMN_NAT_REAL_IP4_1,
	COLUMN_NAT_REAL_PORT_0,
	COLUMN_NAT_REAL_PORT_1,
	COLUMN_NAT_SOURCE,
	COLUMN_NEW_FLOW,
	COLUMN_OBSERVATION_POINT,
	COLUMN_OFFSET,
	COLUMN_OOO_TX,
	COLUMN_OOO_RX,
	COLUMN_PACKET,
	COLUMN_PACKET_BATCH,
	COLUMN_PACKET_COUNT,
	COLUMN_PACKET_RX,
	COLUMN_PACKET_TX,
	COLUMN_PARENT_SPAN_ID,
	COLUMN_POD_CLUSTER_ID,
	COLUMN_POD_CLUSTER_ID_0,
	COLUMN_POD_CLUSTER_ID_1,
	COLUMN_POD_GROUP_ID,
	COLUMN_POD_GROUP_ID_0,
	COLUMN_POD_GROUP_ID_1,
	COLUMN_POD_ID,
	COLUMN_POD_ID_0,
	COLUMN_POD_ID_1,
	COLUMN_POD_NODE_ID,
	COLUMN_POD_NODE_ID_0,
	COLUMN_POD_NODE_ID_1,
	COLUMN_POD_NS_ID,
	COLUMN_POD_NS_ID_0,
	COLUMN_POD_NS_ID_1,
	COLUMN_POLICY_ID,
	COLUMN_POLICY_TYPE,
	COLUMN_PROCESS_ID,
	COLUMN_PROCESS_ID_0,
	COLUMN_PROCESS_ID_1,
	COLUMN_PROCESS_KNAME,
	COLUMN_PROCESS_KNAME_0,
	COLUMN_PROCESS_KNAME_1,
	COLUMN_PROCESS_START_TIME,
	COLUMN_PROFILE_CREATE_TIMESTAMP,
	COLUMN_PROFILE_EVENT_TYPE,
	COLUMN_PROFILE_ID,
	COLUMN_PROFILE_IN_TIMESTAMP,
	COLUMN_PROFILE_LANGUAGE_TYPE,
	COLUMN_PROFILE_LOCATION_STR,
	COLUMN_PROFILE_VALUE,
	COLUMN_PROFILE_VALUE_UNIT,
	COLUMN_PROTOCOL,
	COLUMN_PROVINCE_0,
	COLUMN_PROVINCE_1,
	COLUMN_REGION_ID,
	COLUMN_REGION_ID_0,
	COLUMN_REGION_ID_1,
	COLUMN_REQUEST,
	COLUMN_REQUEST_DOMAIN,
	COLUMN_REQUEST_ID,
	COLUMN_REQUEST_LENGTH,
	COLUMN_REQUEST_RESOURCE,
	COLUMN_REQUEST_TYPE,
	COLUMN_REQ_TCP_SEQ,
	COLUMN_RESPONSE,
	COLUMN_RESPONSE_CODE,
	COLUMN_RESPONSE_DURATION,
	COLUMN_RESPONSE_EXCEPTION,
	COLUMN_RESPONSE_LENGTH,
	COLUMN_RESPONSE_RESULT,
	COLUMN_RESPONSE_STATUS,
	COLUMN_RESP_TCP_SEQ,
	COLUMN_RETRANS,
	COLUMN_RETRANS_RX,
	COLUMN_RETRANS_SYN,
	COLUMN_RETRANS_SYNACK,
	COLUMN_RETRANS_TX,
	COLUMN_ROLE,
	COLUMN_RRT_COUNT,
	COLUMN_RRT_MAX,
	COLUMN_RRT_SUM,
	COLUMN_RTT,
	COLUMN_RTT_CLIENT,
	COLUMN_RTT_CLIENT_COUNT,
	COLUMN_RTT_CLIENT_MAX,
	COLUMN_RTT_CLIENT_SUM,
	COLUMN_RTT_COUNT,
	COLUMN_RTT_MAX,
	COLUMN_RTT_SERVER,
	COLUMN_RTT_SERVER_COUNT,
	COLUMN_RTT_SERVER_MAX,
	COLUMN_RTT_SERVER_SUM,
	COLUMN_RTT_SUM,
	COLUMN_SEARCH_INDEX,
	COLUMN_SERVER_ERROR,
	COLUMN_SERVER_ESTABLISH_FAIL,
	COLUMN_SERVER_ESTABLISH_OTHER_RST,
	COLUMN_SERVER_HALF_CLOSE_FLOW,
	COLUMN_SERVER_PORT,
	COLUMN_SERVER_QUEUE_LACK,
	COLUMN_SERVER_RESET,
	COLUMN_SERVER_RST_FLOW,
	COLUMN_SERVER_SYN_MISS,
	COLUMN_SERVICE_ID,
	COLUMN_SERVICE_ID_0,
	COLUMN_SERVICE_ID_1,
	COLUMN_SEVERITY_NUMBER,
	COLUMN_SIGNAL_SOURCE,
	COLUMN_SPAN_ID,
	COLUMN_SPAN_KIND,
	COLUMN_SPAN_NAME,
	COLUMN_SQL_AFFECTED_ROWS,
	COLUMN_SRT_COUNT,
	COLUMN_SRT_MAX,
	COLUMN_SRT_SUM,
	COLUMN_START_TIME,
	COLUMN_STATUS,
	COLUMN_SUBNET_ID,
	COLUMN_SUBNET_ID_0,
	COLUMN_SUBNET_ID_1,
	COLUMN_SYNACK_COUNT,
	COLUMN_SYN_ACK_SEQ,
	COLUMN_SYN_COUNT,
	COLUMN_SYN_SEQ,
	COLUMN_SYSCALL_CAP_SEQ_0,
	COLUMN_SYSCALL_CAP_SEQ_1,
	COLUMN_SYSCALL_COROUTINE,
	COLUMN_SYSCALL_COROUTINE_0,
	COLUMN_SYSCALL_COROUTINE_1,
	COLUMN_SYSCALL_THREAD,
	COLUMN_SYSCALL_THREAD_0,
	COLUMN_SYSCALL_THREAD_1,
	COLUMN_SYSCALL_TRACE_ID_REQUEST,
	COLUMN_SYSCALL_TRACE_ID_RESPONSE,
	COLUMN_TABLE,
	COLUMN_TAGGED,
	COLUMN_TAG_INT_NAMES,
	COLUMN_TAG_INT_VALUES,
	COLUMN_TAG_NAMES,
	COLUMN_TAG_SOURCE,
	COLUMN_TAG_SOURCE_0,
	COLUMN_TAG_SOURCE_1,
	COLUMN_TAG_STRING_NAMES,
	COLUMN_TAG_STRING_VALUES,
	COLUMN_TAG_VALUES,
	COLUMN_TARGET_ID,
	COLUMN_TARGET_TAGS,
	COLUMN_TCP_ESTABLISH_FAIL,
	COLUMN_TCP_FLAGS_BIT_0,
	COLUMN_TCP_FLAGS_BIT_1,
	COLUMN_TCP_RST_FAIL,
	COLUMN_TCP_TIMEOUT,
	COLUMN_TCP_TRANSFER_FAIL,
	COLUMN_TEAM_ID,
	COLUMN_TIME,
	COLUMN_TIMEOUT,
	COLUMN_TIMESTAMP,
	COLUMN_TLS_RTT,
	COLUMN_TOTAL_BYTE_RX,
	COLUMN_TOTAL_BYTE_TX,
	COLUMN_TOTAL_PACKET_RX,
	COLUMN_TOTAL_PACKET_TX,
	COLUMN_TRACE_FLAGS,
	COLUMN_TRACE_ID,
	COLUMN_TRACE_ID_INDEX,
	COLUMN_TRIGGER_THRESHOLD,
	COLUMN_TUNNEL_IP_ID,
	COLUMN_TUNNEL_IS_IPV4,
	COLUMN_TUNNEL_RX_ID,
	COLUMN_TUNNEL_RX_IP4_0,
	COLUMN_TUNNEL_RX_IP4_1,
	COLUMN_TUNNEL_RX_IP6_0,
	COLUMN_TUNNEL_RX_IP6_1,
	COLUMN_TUNNEL_RX_MAC_0,
	COLUMN_TUNNEL_RX_MAC_1,
	COLUMN_TUNNEL_TIER,
	COLUMN_TUNNEL_TX_ID,
	COLUMN_TUNNEL_TX_IP4_0,
	COLUMN_TUNNEL_TX_IP4_1,
	COLUMN_TUNNEL_TX_IP6_0,
	COLUMN_TUNNEL_TX_IP6_1,
	COLUMN_TUNNEL_TX_MAC_0,
	COLUMN_TUNNEL_TX_MAC_1,
	COLUMN_TUNNEL_TYPE,
	COLUMN_TYPE,
	COLUMN_USER_ID,
	COLUMN_VALUE,
	COLUMN_VERSION,
	COLUMN_VIRTUAL_TABLE_NAME,
	COLUMN_VLAN,
	COLUMN_VPC_ID,
	COLUMN_X_REQUEST_ID_0,
	COLUMN_X_REQUEST_ID_1,
	COLUMN_ZERO_WIN,
	COLUMN_ZERO_WIN_RX,
	COLUMN_ZERO_WIN_TX,
	COLUMN__ID,
	COLUMN__QUERY_REGION,
	COLUMN__TARGET_UID,
	COLUMN__TID,
	COLUMN__TYPE,
}
