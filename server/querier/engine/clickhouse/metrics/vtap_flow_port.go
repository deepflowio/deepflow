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

package metrics

var VTAP_FLOW_PORT_METRICS = map[string]*Metrics{}

var VTAP_FLOW_PORT_METRICS_REPLACE = map[string]*Metrics{
	"l3_byte": NewReplaceMetrics("l3_byte_tx+l3_byte_rx", ""),
	"l4_byte": NewReplaceMetrics("l4_byte_tx+l4_byte_rx", ""),
	"bpp":     NewReplaceMetrics("byte/packet", ""),
	"bpp_tx":  NewReplaceMetrics("byte_tx/packet_tx", ""),
	"bpp_rx":  NewReplaceMetrics("byte_rx/packet_rx", ""),

	"rtt":        NewReplaceMetrics("rtt_sum/rtt_count", ""),
	"rtt_client": NewReplaceMetrics("rtt_client_sum/rtt_client_count", ""),
	"rtt_server": NewReplaceMetrics("rtt_server_sum/rtt_server_count", ""),
	"srt":        NewReplaceMetrics("srt_sum/srt_count", ""),
	"art":        NewReplaceMetrics("art_sum/art_count", ""),
	"rrt":        NewReplaceMetrics("rrt_sum/rrt_count", ""),
	"cit":        NewReplaceMetrics("cit_sum/cit_count", ""),

	"retrans_syn_ratio":    NewReplaceMetrics("retrans_syn/syn_count", ""),
	"retrans_synack_ratio": NewReplaceMetrics("retrans_synack/synack_count", ""),
	"retrans_ratio":        NewReplaceMetrics("retrans/packet", ""),
	"retrans_tx_ratio":     NewReplaceMetrics("retrans_tx/packet_tx", ""),
	"retrans_rx_ratio":     NewReplaceMetrics("retrans_rx/packet_rx", ""),
	"zero_win_ratio":       NewReplaceMetrics("zero_win/packet", ""),
	"zero_win_tx_ratio":    NewReplaceMetrics("zero_win_tx/packet_tx", ""),
	"zero_win_rx_ratio":    NewReplaceMetrics("zero_win_rx/packet_rx", ""),

	"tcp_establish_fail_ratio":    NewReplaceMetrics("tcp_establish_fail/closed_flow", ""),
	"client_establish_fail_ratio": NewReplaceMetrics("client_establish_fail/closed_flow", ""),
	"server_establish_fail_ratio": NewReplaceMetrics("server_establish_fail/closed_flow", ""),
	"tcp_transfer_fail_ratio":     NewReplaceMetrics("tcp_transfer_fail/closed_flow", ""),
	"tcp_rst_fail_ratio":          NewReplaceMetrics("tcp_rst_fail/closed_flow", ""),

	"l7_error_ratio":        NewReplaceMetrics("l7_error/l7_response", ""),
	"l7_client_error_ratio": NewReplaceMetrics("l7_client_error/l7_response", ""),
	"l7_server_error_ratio": NewReplaceMetrics("l7_server_error/l7_response", ""),

	"vpc":         NewReplaceMetrics("l3_epc_id", "NOT (l3_epc_id = -2)"),
	"subnet":      NewReplaceMetrics("subnet_id", "NOT (subnet_id = 0)"),
	"ip":          NewReplaceMetrics("[toString(ip4), toString(subnet_id), toString(is_ipv4), toString(ip6)]", "NOT (((is_ipv4 = 1) OR (ip6 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4 = toIPv4('0.0.0.0'))))"),
	"pod_cluster": NewReplaceMetrics("pod_cluster_id", "NOT (pod_cluster_id = 0)"),
	"pod_node":    NewReplaceMetrics("pod_node_id", "NOT (pod_node_id = 0)"),
	"pod_ns":      NewReplaceMetrics("pod_ns_id", "NOT (pod_ns_id = 0)"),
	"pod_group":   NewReplaceMetrics("pod_group_id", "NOT (pod_group_id = 0)"),
	"pod":         NewReplaceMetrics("pod_id", "NOT (pod_id = 0)"),
	"host":        NewReplaceMetrics("host_id", "NOT (host_id = 0)"),
	"chost":       NewReplaceMetrics("[l3_device_id, l3_device_type]", "(NOT (l3_device_id = 0)) AND (l3_device_type = 1)"),
	"region":      NewReplaceMetrics("region_id", "NOT (region_id = 0)"),
	"az":          NewReplaceMetrics("az_id", "NOT (az_id = 0)"),
}

func GetVtapFlowPortMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return VTAP_FLOW_PORT_METRICS
}
