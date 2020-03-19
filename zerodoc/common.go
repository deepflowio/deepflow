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
	_TAG_REGION_0
	_TAG_IP_1
	_TAG_GROUP_ID_1
	_TAG_L3_EPC_ID_1
	_TAG_L3_DEVICE_ID_1
	_TAG_L3_DEVICE_TYPE_1
	_TAG_HOST_ID_1
	_TAG_SUBNET_ID_0
	_TAG_SUBNET_ID_1
	_TAG_REGION_1
	_TAG_POD_NODE_ID_1
	_TAG_AZ_ID_1
	_TAG_DIRECTION
	_TAG_ACL_GID
	_TAG_VLAN_ID
	_TAG_PROTOCOL
	_TAG_SERVER_PORT
	_TAG_VTAP_ID
	_TAG_TAP_TYPE
	_TAG_SUBNET_ID
	_TAG_ACL_DIRECTION
	_TAG_CAST_TYPE
	_TAG_TCP_FLAGS
	_TAG_TUNNEL_IP_ID
	_TAG_COUNTRY
	_TAG_REGION
	_TAG_PROVINCE
	_TAG_ISP
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
	_METER_CLIENT_RST_FLOW
	_METER_SERVER_RST_FLOW
	_METER_CLIENT_HALF_OPEN_FLOW
	_METER_SERVER_HALF_OPEN_FLOW
	_METER_CLIENT_HALF_CLOSE_FLOW
	_METER_SERVER_HALF_CLOSE_FLOW
	_METER_TIMEOUT_TCP_FLOW
	_METER_RTT_SUM
	_METER_RTT_CLIENT_SUM
	_METER_RTT_SERVER_SUM
	_METER_SRT_SUM
	_METER_ART_SUM
	_METER_RTT_COUNT
	_METER_RTT_CLIENT_COUNT
	_METER_RTT_SERVER_COUNT
	_METER_SRT_COUNT
	_METER_ART_COUNT
	_METER_RETRANS_TX
	_METER_RETRANS_RX
	_METER_ZERO_WIN_TX
	_METER_ZERO_WIN_RX
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
	"region":           _TAG_REGION,
	"region_0":         _TAG_REGION_0,
	"ip_1":             _TAG_IP_1,
	"group_id_1":       _TAG_GROUP_ID_1,
	"l3_epc_id_1":      _TAG_L3_EPC_ID_1,
	"l3_device_id_1":   _TAG_L3_DEVICE_ID_1,
	"l3_device_type_1": _TAG_L3_DEVICE_TYPE_1,
	"host_id_1":        _TAG_HOST_ID_1,
	"subnet_id_0":      _TAG_SUBNET_ID_0,
	"subnet_id_1":      _TAG_SUBNET_ID_1,
	"region_1":         _TAG_REGION_1,
	"pod_node_id_1":    _TAG_POD_NODE_ID_1,
	"az_id_1":          _TAG_AZ_ID_1,
	"direction":        _TAG_DIRECTION,
	"acl_gid":          _TAG_ACL_GID,
	"vlan_id":          _TAG_VLAN_ID,
	"protocol":         _TAG_PROTOCOL,
	"server_port":      _TAG_SERVER_PORT,
	"vtap_id":          _TAG_VTAP_ID,
	"tap_type":         _TAG_TAP_TYPE,
	"subnet_id":        _TAG_SUBNET_ID,
	"acl_direction":    _TAG_ACL_DIRECTION,
	"cast_type":        _TAG_CAST_TYPE,
	"tcp_flags":        _TAG_TCP_FLAGS,
	"country":          _TAG_COUNTRY,
	"province":         _TAG_PROVINCE,
	"isp":              _TAG_ISP,

	"packet_tx":              _METER_PACKET_TX,
	"packet_rx":              _METER_PACKET_RX,
	"byte_tx":                _METER_BYTE_TX,
	"byte_rx":                _METER_BYTE_RX,
	"flow":                   _METER_FLOW,
	"new_flow":               _METER_NEW_FLOW,
	"closed_flow":            _METER_CLOSED_FLOW,
	"client_rst_flow":        _METER_CLIENT_RST_FLOW,
	"server_rst_flow":        _METER_SERVER_RST_FLOW,
	"client_half_open_flow":  _METER_CLIENT_HALF_OPEN_FLOW,
	"server_half_open_flow":  _METER_SERVER_HALF_OPEN_FLOW,
	"client_half_close_flow": _METER_CLIENT_HALF_CLOSE_FLOW,
	"server_half_close_flow": _METER_SERVER_HALF_CLOSE_FLOW,
	"timeout_tcp_flow":       _METER_TIMEOUT_TCP_FLOW,
	"rtt_sum":                _METER_RTT_SUM,
	"rtt_client_sum":         _METER_RTT_CLIENT_SUM,
	"rtt_server_sum":         _METER_RTT_SERVER_SUM,
	"srt_sum":                _METER_SRT_SUM,
	"art_sum":                _METER_ART_SUM,
	"rtt_count":              _METER_RTT_COUNT,
	"rtt_client_count":       _METER_RTT_CLIENT_COUNT,
	"rtt_server_count":       _METER_RTT_SERVER_COUNT,
	"srt_count":              _METER_SRT_COUNT,
	"art_count":              _METER_ART_COUNT,
	"retrans_tx":             _METER_RETRANS_TX,
	"retrans_rx":             _METER_RETRANS_RX,
	"zero_win_tx":            _METER_ZERO_WIN_TX,
	"zero_win_rx":            _METER_ZERO_WIN_RX,
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
