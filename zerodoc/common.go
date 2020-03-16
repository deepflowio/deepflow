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
	_TAG_COUNTRY
	_TAG_REGION
	_TAG_ISP
	_TAG_MAX_ID_
)
const (
	_METER_INVALID_ uint8 = 128 + iota
	_METER_BYTES
	_METER_MAX_ART_AVG
	_METER_MAX_RTT_AVG
	_METER_MAX_RTT_SYN
	_METER_MAX_RTT_SYN_CLIENT
	_METER_MAX_RTT_SYN_SERVER
	_METER_PACKETS
	_METER_RX_BYTES
	_METER_RX_PACKETS
	_METER_SUM_ART_AVG
	_METER_SUM_ART_AVG_FLOW
	_METER_SUM_BIT_RX
	_METER_SUM_BIT_TX
	_METER_SUM_CLOSED_FLOW_COUNT
	_METER_SUM_COUNT_T_C_HALF_CLOSE
	_METER_SUM_COUNT_T_C_HALF_OPEN
	_METER_SUM_COUNT_T_C_RST
	_METER_SUM_COUNT_T_S_HALF_CLOSE
	_METER_SUM_COUNT_T_S_HALF_OPEN
	_METER_SUM_COUNT_T_S_RST
	_METER_SUM_FLOW_COUNT
	_METER_SUM_HALF_OPEN_FLOW_COUNT
	_METER_SUM_NEW_FLOW_COUNT
	_METER_SUM_PACKET_RX
	_METER_SUM_PACKET_TX
	_METER_SUM_RETRANS_CNT_RX
	_METER_SUM_RETRANS_CNT_TX
	_METER_SUM_RTT_AVG
	_METER_SUM_RTT_AVG_FLOW
	_METER_SUM_RTT_SYN
	_METER_SUM_RTT_SYN_CLIENT
	_METER_SUM_RTT_SYN_CLIENT_FLOW
	_METER_SUM_RTT_SYN_FLOW
	_METER_SUM_ZERO_WND_CNT_RX
	_METER_SUM_ZERO_WND_CNT_TX
	_METER_TX_BYTES
	_METER_TX_PACKETS
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
	"region":           _TAG_REGION,
	"isp":              _TAG_ISP,

	"bytes":                    _METER_BYTES,
	"max_art_avg":              _METER_MAX_ART_AVG,
	"max_rtt_avg":              _METER_MAX_RTT_AVG,
	"max_rtt_syn":              _METER_MAX_RTT_SYN,
	"max_rtt_syn_client":       _METER_MAX_RTT_SYN_CLIENT,
	"max_rtt_syn_server":       _METER_MAX_RTT_SYN_SERVER,
	"packets":                  _METER_PACKETS,
	"rx_bytes":                 _METER_RX_BYTES,
	"rx_packets":               _METER_RX_PACKETS,
	"sum_art_avg":              _METER_SUM_ART_AVG,
	"sum_art_avg_flow":         _METER_SUM_ART_AVG_FLOW,
	"sum_bit_rx":               _METER_SUM_BIT_RX,
	"sum_bit_tx":               _METER_SUM_BIT_TX,
	"sum_closed_flow_count":    _METER_SUM_CLOSED_FLOW_COUNT,
	"sum_count_t_c_half_close": _METER_SUM_COUNT_T_C_HALF_CLOSE,
	"sum_count_t_c_half_open":  _METER_SUM_COUNT_T_C_HALF_OPEN,
	"sum_count_t_c_rst":        _METER_SUM_COUNT_T_C_RST,
	"sum_count_t_s_half_close": _METER_SUM_COUNT_T_S_HALF_CLOSE,
	"sum_count_t_s_half_open":  _METER_SUM_COUNT_T_S_HALF_OPEN,
	"sum_count_t_s_rst":        _METER_SUM_COUNT_T_S_RST,
	"sum_flow_count":           _METER_SUM_FLOW_COUNT,
	"sum_half_open_flow_count": _METER_SUM_HALF_OPEN_FLOW_COUNT,
	"sum_new_flow_count":       _METER_SUM_NEW_FLOW_COUNT,
	"sum_packet_rx":            _METER_SUM_PACKET_RX,
	"sum_packet_tx":            _METER_SUM_PACKET_TX,
	"sum_retrans_cnt_rx":       _METER_SUM_RETRANS_CNT_RX,
	"sum_retrans_cnt_tx":       _METER_SUM_RETRANS_CNT_TX,
	"sum_rtt_avg":              _METER_SUM_RTT_AVG,
	"sum_rtt_avg_flow":         _METER_SUM_RTT_AVG_FLOW,
	"sum_rtt_syn":              _METER_SUM_RTT_SYN,
	"sum_rtt_syn_client":       _METER_SUM_RTT_SYN_CLIENT,
	"sum_rtt_syn_client_flow":  _METER_SUM_RTT_SYN_CLIENT_FLOW,
	"sum_rtt_syn_flow":         _METER_SUM_RTT_SYN_FLOW,
	"sum_zero_wnd_cnt_rx":      _METER_SUM_ZERO_WND_CNT_RX,
	"sum_zero_wnd_cnt_tx":      _METER_SUM_ZERO_WND_CNT_TX,
	"tx_bytes":                 _METER_TX_BYTES,
	"tx_packets":               _METER_TX_PACKETS,
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
