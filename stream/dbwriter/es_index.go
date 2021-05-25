package dbwriter

import (
	"encoding/json"
	"fmt"
	"strconv"

	"gitlab.x.lan/yunshan/droplet/stream/common"
)

func buildJsonBody(name string, replica int, tiering bool) string {
	body := map[string]interface{}{
		"index_patterns": name + common.LOG_SUFFIX,
		"settings":       buildSettings(replica, tiering),
		"mappings":       DFMappingsJson[name],
	}

	jsonStr, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	return string(jsonStr)
}

func buildSettings(replica int, tiering bool) map[string]interface{} {
	var settings = map[string]interface{}{
		"index.refresh_interval":    "10s",
		"number_of_shards":          "11",
		"index.translog.durability": "async",
		"index.number_of_replicas":  strconv.Itoa(replica),
	}
	if tiering {
		settings["index.routing.allocation.require.box_type"] = "warm"
	}

	return settings
}

var boolean_property = map[string]interface{}{"type": "boolean", "store": true}
var integer_property = map[string]interface{}{"type": "integer", "store": true}
var long_property = map[string]interface{}{"type": "long", "store": true}
var string_property = map[string]interface{}{"type": "keyword", "store": true}
var binary_property = map[string]interface{}{"type": "binary", "doc_values": false, "store": true}
var epoch_property = map[string]interface{}{"type": "date", "format": "epoch_second", "store": true}
var epoch_millis_property = map[string]interface{}{"type": "date", "format": "epoch_millis", "store": true}
var ip_property = map[string]interface{}{"type": "ip", "store": true}

// 所有支持模糊搜索的字段
var analyzed_string_property = map[string]interface{}{"type": "text", "store": true, "index": true}

// 无索引类型
var simple_long_property = map[string]interface{}{"type": "long", "store": true, "index": false}
var simple_integer_property = map[string]interface{}{"type": "integer", "store": true, "index": false}
var simple_string_property = map[string]interface{}{"type": "keyword", "store": true, "index": false}
var simple_boolean_property = map[string]interface{}{"type": "boolean", "store": true, "index": false}
var simple_ip_property = map[string]interface{}{"type": "ip", "store": true, "index": false}

var DFMappings = make(map[string]string)
var DFMappingsJson = make(map[string]map[string]interface{})

func init() {
	DFMappingsJson[common.L4_FLOW_ID.String()] = DFI_FLOW
	DFMappingsJson[common.L7_HTTP_ID.String()] = DFI_HTTP
	DFMappingsJson[common.L7_DNS_ID.String()] = DFI_DNS

	for k, v := range DFMappingsJson {
		if jsonStr, err := json.Marshal(v); err != nil {
			panic(fmt.Sprintf("Marshal %s failed: %s", k, err))
		} else {
			DFMappings[k] = string(jsonStr)
		}
	}
}

var DFI_FLOW = map[string]interface{}{
	"flow": map[string]interface{}{
		"_source": map[string]interface{}{
			"enabled": false,
		},
		"dynamic": true,
		"properties": map[string]interface{}{
			// 链路层
			"mac_0":    simple_long_property,
			"mac_1":    simple_long_property,
			"eth_type": integer_property,
			"vlan":     simple_integer_property,

			// 网络层
			"ip4_0":          ip_property,
			"ip4_1":          ip_property,
			"ip6_0":          ip_property,
			"ip6_1":          ip_property,
			"is_ipv4":        boolean_property,
			"protocol":       integer_property,
			"tunnel_tier":    simple_integer_property,
			"tunnel_type":    simple_integer_property,
			"tunnel_tx_id":   simple_integer_property,
			"tunnel_tx_ip_0": simple_string_property,
			"tunnel_tx_ip_1": simple_string_property,
			"tunnel_rx_id":   simple_integer_property,
			"tunnel_rx_ip_0": simple_string_property,
			"tunnel_rx_ip_1": simple_string_property,

			// 传输层
			"client_port":     integer_property,
			"server_port":     integer_property,
			"tcp_flags_bit_0": simple_integer_property,
			"tcp_flags_bit_1": simple_integer_property,

			// 应用层
			"l7_protocol": integer_property,

			// 广域网
			"province_0": string_property,
			"province_1": string_property,

			// 知识图谱
			"region_id_0":      integer_property,
			"region_id_1":      integer_property,
			"az_id_0":          integer_property,
			"az_id_1":          integer_property,
			"host_id_0":        integer_property,
			"host_id_1":        integer_property,
			"l3_device_type_0": integer_property,
			"l3_device_type_1": integer_property,
			"l3_device_id_0":   integer_property,
			"l3_device_id_1":   integer_property,
			"pod_node_id_0":    integer_property,
			"pod_node_id_1":    integer_property,
			"pod_ns_id_0":      integer_property,
			"pod_ns_id_1":      integer_property,
			"pod_group_id_0":   integer_property,
			"pod_group_id_1":   integer_property,
			"pod_id_0":         integer_property,
			"pod_id_1":         integer_property,
			"pod_cluster_id_0": integer_property,
			"pod_cluster_id_1": integer_property,
			"l3_epc_id_0":      integer_property,
			"l3_epc_id_1":      integer_property,
			"epc_id_0":         simple_integer_property,
			"epc_id_1":         simple_integer_property,
			"subnet_id_0":      integer_property,
			"subnet_id_1":      integer_property,

			// 流信息
			"close_type":  integer_property,
			"flow_source": simple_integer_property,
			"flow_id_str": long_property,
			"tap_type":    integer_property,
			"tap_port":    integer_property,
			"vtap_id":     integer_property,
			"l2_end_0":    simple_boolean_property,
			"l2_end_1":    simple_boolean_property,
			"l3_end_0":    simple_boolean_property,
			"l3_end_1":    simple_boolean_property,
			"start_time":  epoch_property,
			"end_time":    epoch_property,
			"duration":    simple_long_property,

			// 指标量
			"packet_tx":         simple_long_property,
			"packet_rx":         simple_long_property,
			"byte_tx":           simple_long_property,
			"byte_rx":           simple_long_property,
			"l3_byte_tx":        simple_long_property,
			"l3_byte_rx":        simple_long_property,
			"l4_byte_tx":        simple_long_property,
			"l4_byte_rx":        simple_long_property,
			"total_packet_tx":   simple_long_property,
			"total_packet_rx":   simple_long_property,
			"total_byte_tx":     simple_long_property,
			"total_byte_rx":     simple_long_property,
			"l7_request":        simple_integer_property,
			"l7_response":       simple_integer_property,
			"rtt_client":        simple_integer_property,
			"rtt_server":        simple_integer_property,
			"rtt":               simple_integer_property,
			"srt":               simple_integer_property,
			"art":               simple_integer_property,
			"rrt":               simple_integer_property,
			"rtt_client_max":    simple_integer_property,
			"rtt_server_max":    simple_integer_property,
			"srt_max":           simple_integer_property,
			"art_max":           simple_integer_property,
			"rrt_max":           simple_integer_property,
			"retans_tx":         simple_integer_property,
			"retrans_rx":        simple_integer_property,
			"zero_win_tx":       simple_integer_property,
			"zero_win_rx":       simple_integer_property,
			"l7_client_error":   simple_integer_property,
			"l7_server_error":   simple_integer_property,
			"l7_server_timeout": simple_integer_property,
		},
	},
}

var DFI_HTTP = map[string]interface{}{
	"flow": map[string]interface{}{
		"_source": map[string]interface{}{
			"enabled": false,
		},
		"dynamic": true,
		"properties": map[string]interface{}{
			// 网络层
			"ip4_0": ip_property,
			"ip4_1": ip_property,
			"ip6_0": ip_property,
			"ip6_1": ip_property,

			// 传输层
			"client_port": integer_property,
			"server_port": integer_property,

			// 知识图谱
			"region_id_0":      integer_property,
			"region_id_1":      integer_property,
			"az_id_0":          integer_property,
			"az_id_1":          integer_property,
			"host_id_0":        integer_property,
			"host_id_1":        integer_property,
			"l3_device_type_0": integer_property,
			"l3_device_type_1": integer_property,
			"l3_device_id_0":   integer_property,
			"l3_device_id_1":   integer_property,
			"pod_node_id_0":    integer_property,
			"pod_node_id_1":    integer_property,
			"pod_ns_id_0":      integer_property,
			"pod_ns_id_1":      integer_property,
			"pod_group_id_0":   integer_property,
			"pod_group_id_1":   integer_property,
			"pod_id_0":         integer_property,
			"pod_id_1":         integer_property,
			"pod_cluster_id_0": integer_property,
			"pod_cluster_id_1": integer_property,
			"l3_epc_id_0":      integer_property,
			"l3_epc_id_1":      integer_property,
			"epc_id_0":         simple_integer_property,
			"epc_id_1":         simple_integer_property,
			"subnet_id_0":      integer_property,
			"subnet_id_1":      integer_property,

			// 流信息
			"flow_id_str": long_property,
			"tap_type":    integer_property,
			"tap_port":    string_property,
			"vtap_id":     integer_property,
			"timestamp":   long_property,
			"time":        epoch_property,

			// 应用层HTTP
			"type":           simple_integer_property,
			"version":        simple_integer_property,
			"method":         simple_string_property,
			"client_ip4":     simple_ip_property,
			"client_ip6":     simple_ip_property,
			"client_is_ipv4": simple_boolean_property,
			"host":           simple_string_property,
			"path":           simple_string_property,
			"stream_id":      simple_long_property,
			"trace_id":       simple_string_property,
			"status_code":    simple_integer_property,

			// 指标量
			"content_length": simple_long_property,
			"duration":       simple_long_property,
		},
	},
}

var DFI_DNS = map[string]interface{}{
	"flow": map[string]interface{}{
		"_source": map[string]interface{}{
			"enabled": false,
		},
		"dynamic": true,
		"properties": map[string]interface{}{
			// 网络层
			"ip4_0":   ip_property,
			"ip4_1":   ip_property,
			"ip6_0":   ip_property,
			"ip6_1":   ip_property,
			"is_ipv4": boolean_property,

			// 传输层
			"client_port": integer_property,
			"server_port": integer_property,

			// 知识图谱
			"region_id_0":      integer_property,
			"region_id_1":      integer_property,
			"az_id_0":          integer_property,
			"az_id_1":          integer_property,
			"host_id_0":        integer_property,
			"host_id_1":        integer_property,
			"l3_device_type_0": integer_property,
			"l3_device_type_1": integer_property,
			"l3_device_id_0":   integer_property,
			"l3_device_id_1":   integer_property,
			"pod_node_id_0":    integer_property,
			"pod_node_id_1":    integer_property,
			"pod_ns_id_0":      integer_property,
			"pod_ns_id_1":      integer_property,
			"pod_group_id_0":   integer_property,
			"pod_group_id_1":   integer_property,
			"pod_id_0":         integer_property,
			"pod_id_1":         integer_property,
			"pod_cluster_id_0": integer_property,
			"pod_cluster_id_1": integer_property,
			"l3_epc_id_0":      integer_property,
			"l3_epc_id_1":      integer_property,
			"epc_id_0":         simple_integer_property,
			"epc_id_1":         simple_integer_property,
			"subnet_id_0":      integer_property,
			"subnet_id_1":      integer_property,

			// 留信息
			"flow_id_str": string_property,
			"tap_type":    integer_property,
			"tap_port":    integer_property,
			"vtap_id":     integer_property,
			"timestamp":   long_property,
			"time":        epoch_property,

			// 应用层DNS
			"type":        simple_integer_property,
			"id":          simple_integer_property,
			"domain_name": simple_string_property,
			"query_type":  simple_integer_property,
			"answer_code": simple_integer_property,
			"answer_addr": simple_string_property,

			// 指标量
			"duration": simple_long_property,
		},
	},
}
