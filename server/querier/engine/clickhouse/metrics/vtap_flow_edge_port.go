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

var VTAP_FLOW_EDGE_PORT_METRICS = map[string]*Metrics{}

var VTAP_FLOW_EDGE_PORT_METRICS_REPLACE = map[string]*Metrics{
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

	"vpc_0":         NewReplaceMetrics("l3_epc_id_0", "NOT (l3_epc_id_0 = -2)"),
	"subnet_0":      NewReplaceMetrics("subnet_id_0", "NOT (subnet_id_0 = 0)"),
	"ip_0":          NewReplaceMetrics("[toString(ip4_0), toString(is_ipv4), toString(ip6_0)]", "NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))"),
	"pod_cluster_0": NewReplaceMetrics("pod_cluster_id_0", "NOT (pod_cluster_id_0 = 0)"),
	"pod_node_0":    NewReplaceMetrics("pod_node_id_0", "NOT (pod_node_id_0 = 0)"),
	"pod_ns_0":      NewReplaceMetrics("pod_ns_id_0", "NOT (pod_ns_id_0 = 0)"),
	"pod_group_0":   NewReplaceMetrics("pod_group_id_0", "NOT (pod_group_id_0 = 0)"),
	"pod_0":         NewReplaceMetrics("pod_id_0", "NOT (pod_id_0 = 0)"),
	"host_0":        NewReplaceMetrics("host_id_0", "NOT (host_id_0 = 0)"),
	"chost_0":       NewReplaceMetrics("[l3_device_id_0, l3_device_type_0]", "(NOT (l3_device_id_0 = 0)) AND (l3_device_type_0 = 1)"),
	"region_0":      NewReplaceMetrics("region_id_0", "NOT (region_id_0 = 0)"),
	"az_0":          NewReplaceMetrics("az_id_0", "NOT (az_id_0 = 0)"),
	"vpc_1":         NewReplaceMetrics("l3_epc_id_1", "NOT (l3_epc_id_1 = -2)"),
	"subnet_1":      NewReplaceMetrics("subnet_id_1", "NOT (subnet_id_1 = 0)"),
	"ip_1":          NewReplaceMetrics("[toString(ip4_1), toString(subnet_id_1), toString(is_ipv4), toString(ip6_1)]", "NOT (((is_ipv4 = 1) OR (ip6_1 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_1 = toIPv4('0.0.0.0'))))"),
	"pod_cluster_1": NewReplaceMetrics("pod_cluster_id_1", "NOT (pod_cluster_id_1 = 0)"),
	"pod_node_1":    NewReplaceMetrics("pod_node_id_1", "NOT (pod_node_id_1 = 0)"),
	"pod_ns_1":      NewReplaceMetrics("pod_ns_id_1", "NOT (pod_ns_id_1 = 0)"),
	"pod_group_1":   NewReplaceMetrics("pod_group_id_1", "NOT (pod_group_id_1 = 0)"),
	"pod_1":         NewReplaceMetrics("pod_id_1", "NOT (pod_id_1 = 0)"),
	"host_1":        NewReplaceMetrics("host_id_1", "NOT (host_id_1 = 0)"),
	"chost_1":       NewReplaceMetrics("[toString(l3_device_id_1), toString(l3_device_type_1)]", "(NOT (l3_device_id_1 = 0)) AND (l3_device_type_1 = 1)"),
	"region_1":      NewReplaceMetrics("region_id_1", "NOT (region_id_1 = 0)"),
	"az_1":          NewReplaceMetrics("az_id_1", "NOT (az_id_1 = 0)"),
}

func GetVtapFlowEdgePortMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return VTAP_FLOW_EDGE_PORT_METRICS
}
