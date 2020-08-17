package zerodoc

import logging "github.com/op/go-logging"

var log = logging.MustGetLogger("zerodoc")

const (
	_TAG_INVALID_ uint8 = iota
	_TAG__ID
	_TAG__TID
	_TAG_IP_VERSION
	_TAG_IP
	_TAG_IP_0
	_TAG_GROUP_ID
	_TAG_GROUP_ID_0
	_TAG_L3_EPC_ID
	_TAG_L3_EPC_ID_0
	_TAG_L3_DEVICE_ID
	_TAG_L3_DEVICE_ID_0
	_TAG_L3_DEVICE_TYPE
	_TAG_L3_DEVICE_TYPE_0
	_TAG_HOST_ID
	_TAG_HOST_ID_0
	_TAG_POD_NODE_ID
	_TAG_POD_NODE_ID_0
	_TAG_AZ_ID
	_TAG_AZ_ID_0
	_TAG_REGION_ID_0
	_TAG_IP_1
	_TAG_GROUP_ID_1
	_TAG_L3_EPC_ID_1
	_TAG_L3_DEVICE_ID_1
	_TAG_L3_DEVICE_TYPE_1
	_TAG_HOST_ID_1
	_TAG_SUBNET_ID_0
	_TAG_SUBNET_ID_1
	_TAG_REGION_ID_1
	_TAG_POD_NODE_ID_1
	_TAG_AZ_ID_1
	_TAG_DIRECTION
	_TAG_ACL_GID
	_TAG_VLAN_ID
	_TAG_PROTOCOL
	_TAG_SERVER_PORT
	_TAG_VTAP_ID
	_TAG_TAP_SIDE
	_TAG_TAP_TYPE
	_TAG_SUBNET_ID
	_TAG_ACL_DIRECTION
	_TAG_REGION_ID
	_TAG_TAG_TYPE
	_TAG_TAG_VALUE
	_TAG_POD_GROUP_ID
	_TAG_POD_GROUP_ID_0
	_TAG_POD_GROUP_ID_1
	_TAG_POD_NS_ID
	_TAG_POD_NS_ID_0
	_TAG_POD_NS_ID_1
	_TAG_MAX_ID_
)
const (
	_METER_INVALID_ uint8 = 128 + iota
	_METER_PACKET_TX
	_METER_PACKET_RX
	_METER_BYTE_TX
	_METER_BYTE_RX
	_METER_FLOW
	_METER_NEW_FLOW
	_METER_CLOSED_FLOW
	_METER_HTTP_REQUEST
	_METER_HTTP_RESPONSE
	_METER_DNS_REQUEST
	_METER_DNS_RESPONSE

	_METER_CLIENT_RST_FLOW
	_METER_SERVER_RST_FLOW
	_METER_CLIENT_SYN_REPEAT
	_METER_SERVER_SYN_ACK_REPEAT
	_METER_CLIENT_HALF_CLOSE_FLOW
	_METER_SERVER_HALF_CLOSE_FLOW
	_METER_CLIENT_NO_RESPONSE
	_METER_CLIENT_SOURCE_PORT_REUSE
	_METER_CLIENT_SYN_RETRY_LACK
	_METER_SERVER_RESET
	_METER_SERVER_NO_RESPONSE
	_METER_SERVER_QUEUE_LACK
	_METER_HTTP_CLIENT_ERROR
	_METER_HTTP_SERVER_ERROR
	_METER_DNS_CLIENT_ERROR
	_METER_DNS_SERVER_ERROR

	_METER_RTT
	_METER_RTT_CLIENT
	_METER_RTT_SERVER
	_METER_SRT
	_METER_ART
	_METER_HTTP_RRT
	_METER_DNS_RRT
	_METER_RETRANS_TX
	_METER_RETRANS_RX
	_METER_ZERO_WIN_TX
	_METER_ZERO_WIN_RX

	_METER_FLOW_LOAD_MAX
	_METER_FLOW_LOAD_MIN
	_METER_MAX_ID_
)

const (
	// influxdb固定有time列, 该ID定义为最大，不属于tag和meter范围, 在EncodeRow中单独处理
	_TIME uint8 = 255
)

var COLUMN_IDS map[string]uint8 = map[string]uint8{
	"time":             _TIME,
	"_id":              _TAG__ID,
	"_tid":             _TAG__TID,
	"ip_version":       _TAG_IP_VERSION,
	"ip":               _TAG_IP,
	"ip_0":             _TAG_IP_0,
	"group_id":         _TAG_GROUP_ID,
	"group_id_0":       _TAG_GROUP_ID_0,
	"l3_epc_id":        _TAG_L3_EPC_ID,
	"l3_epc_id_0":      _TAG_L3_EPC_ID_0,
	"l3_device_id":     _TAG_L3_DEVICE_ID,
	"l3_device_id_0":   _TAG_L3_DEVICE_ID_0,
	"l3_device_type":   _TAG_L3_DEVICE_TYPE,
	"l3_device_type_0": _TAG_L3_DEVICE_TYPE_0,
	"pod_node_id":      _TAG_POD_NODE_ID,
	"pod_node_id_0":    _TAG_POD_NODE_ID_0,
	"az_id":            _TAG_AZ_ID,
	"az_id_0":          _TAG_AZ_ID_0,
	"host_id":          _TAG_HOST_ID,
	"host_id_0":        _TAG_HOST_ID_0,
	"region_id":        _TAG_REGION_ID,
	"region_id_0":      _TAG_REGION_ID_0,
	"ip_1":             _TAG_IP_1,
	"group_id_1":       _TAG_GROUP_ID_1,
	"l3_epc_id_1":      _TAG_L3_EPC_ID_1,
	"l3_device_id_1":   _TAG_L3_DEVICE_ID_1,
	"l3_device_type_1": _TAG_L3_DEVICE_TYPE_1,
	"host_id_1":        _TAG_HOST_ID_1,
	"subnet_id_0":      _TAG_SUBNET_ID_0,
	"subnet_id_1":      _TAG_SUBNET_ID_1,
	"region_id_1":      _TAG_REGION_ID_1,
	"pod_node_id_1":    _TAG_POD_NODE_ID_1,
	"az_id_1":          _TAG_AZ_ID_1,
	"direction":        _TAG_DIRECTION,
	"acl_gid":          _TAG_ACL_GID,
	"vlan_id":          _TAG_VLAN_ID,
	"protocol":         _TAG_PROTOCOL,
	"server_port":      _TAG_SERVER_PORT,
	"vtap_id":          _TAG_VTAP_ID,
	"tap_side":         _TAG_TAP_SIDE,
	"tap_type":         _TAG_TAP_TYPE,
	"subnet_id":        _TAG_SUBNET_ID,
	"acl_direction":    _TAG_ACL_DIRECTION,
	"tag_type":         _TAG_TAG_TYPE,
	"tag_value":        _TAG_TAG_VALUE,
	"pod_group_id":     _TAG_POD_GROUP_ID,
	"pod_group_id_0":   _TAG_POD_GROUP_ID_0,
	"pod_group_id_1":   _TAG_POD_GROUP_ID_1,
	"pod_ns_id":        _TAG_POD_NS_ID,
	"pod_ns_id_0":      _TAG_POD_NS_ID_0,
	"pod_ns_id_1":      _TAG_POD_NS_ID_1,

	"packet_tx":   _METER_PACKET_TX,
	"packet_rx":   _METER_PACKET_RX,
	"byte_tx":     _METER_BYTE_TX,
	"byte_rx":     _METER_BYTE_RX,
	"flow":        _METER_FLOW,
	"new_flow":    _METER_NEW_FLOW,
	"closed_flow": _METER_CLOSED_FLOW,

	"http_request":  _METER_HTTP_REQUEST,
	"http_response": _METER_HTTP_RESPONSE,
	"dns_request":   _METER_DNS_REQUEST,
	"dns_response":  _METER_DNS_RESPONSE,

	"client_rst_flow":       _METER_CLIENT_RST_FLOW,
	"server_rst_flow":       _METER_SERVER_RST_FLOW,
	"server_syn_ack_repeat": _METER_SERVER_SYN_ACK_REPEAT,
	"client_syn_repeat":     _METER_CLIENT_SYN_REPEAT,

	"client_half_close_flow":   _METER_CLIENT_HALF_CLOSE_FLOW,
	"server_half_close_flow":   _METER_SERVER_HALF_CLOSE_FLOW,
	"client_no_response":       _METER_CLIENT_NO_RESPONSE,
	"client_source_port_reuse": _METER_CLIENT_SOURCE_PORT_REUSE,
	"client_syn_retry_lack":    _METER_CLIENT_SYN_RETRY_LACK,
	"server_reset":             _METER_SERVER_RESET,
	"server_no_response":       _METER_SERVER_NO_RESPONSE,
	"server_queue_lack":        _METER_SERVER_QUEUE_LACK,
	"http_client_error":        _METER_HTTP_CLIENT_ERROR,
	"http_server_error":        _METER_HTTP_SERVER_ERROR,
	"dns_client_error":         _METER_DNS_CLIENT_ERROR,
	"dns_server_error":         _METER_DNS_SERVER_ERROR,

	"rtt":        _METER_RTT,
	"rtt_client": _METER_RTT_CLIENT,
	"rtt_server": _METER_RTT_SERVER,
	"srt":        _METER_SRT,
	"art":        _METER_ART,
	"http_rrt":   _METER_HTTP_RRT,
	"dns_rrt":    _METER_DNS_RRT,

	"retrans_tx":  _METER_RETRANS_TX,
	"retrans_rx":  _METER_RETRANS_RX,
	"zero_win_tx": _METER_ZERO_WIN_TX,
	"zero_win_rx": _METER_ZERO_WIN_RX,
}

func GetColumnIDs(columnNames []string) []uint8 {
	b := make([]uint8, len(columnNames))
	for i, name := range columnNames {
		if id, ok := COLUMN_IDS[name]; ok {
			b[i] = id
		} else {
			log.Warningf("unsupport column name(%s)", name)
		}
	}
	return b
}
