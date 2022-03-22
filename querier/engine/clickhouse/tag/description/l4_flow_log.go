package description

var L4FlowLogTags = []*TagDescription{
	// 链路层
	NewTagDescription("mac", "mac_0", "mac_1", "MAC", INT),
	NewTagDescription("eth_type", "eth_type", "eth_type", "链路协议", INT_ENUM),
	NewTagDescription("vlan", "vlan", "vlan", "VLAN", INT),
	//网络层
	NewTagDescription("ip_version", "ip_version", "ip_version", "IP类型", INT_ENUM),
	NewTagDescription("protocol", "protocol", "protocol", "协议", INT_ENUM),
	NewTagDescription("tunnel_tier", "tunnel_tier", "tunnel_tier", "隧道层数", INT_ENUM),
	NewTagDescription("tunnel_type", "tunnel_type", "tunnel_type", "隧道类型", INT_ENUM),
	NewTagDescription("tunnel_tx_id", "tunnel_tx_id", "tunnel_tx_id", "请求隧道ID", INT),
	NewTagDescription("tunnel_rx_id", "tunnel_rx_id", "tunnel_rx_id", "响应隧道ID", INT),
	NewTagDescription("tunnel_tx_ip", "tunnel_tx_ip_0", "tunnel_tx_ip_1", "请求隧道IP", IP),
	NewTagDescription("tunnel_rx_ip", "tunnel_rx_ip_0", "tunnel_rx_ip_1", "响应隧道IP", IP),
	// 传输层
	NewTagDescription("clientport", "clientport", "", "客户端口", INT),
	NewTagDescription("serverport", "", "serverport", "服务端口", INT),
	NewTagDescription("tcp_flags_bit", "tcp_flags_bit_0", "tcp_flags_bit_1", "TCP标志位列表", INT),
	NewTagDescription("syn_seq", "syn_seq", "syn_seq", "SYN SEQ", INT),
	NewTagDescription("syn_ack_seq", "syn_ack_seq", "syn_ack_seq", "SYN-ACK SEQ", INT),
	NewTagDescription("last_keepalive_seq", "last_keepalive_seq", "last_keepalive_seq", "心跳SEQ", INT),
	NewTagDescription("last_keepalive_ack", "last_keepalive_ack", "last_keepalive_ack", "心跳ACK SEQ", INT),
	// 应用层
	NewTagDescription("l7_protocol", "l7_protocol", "l7_protocol", "应用协议", INT_ENUM),
	// 广域网
	NewTagDescription("province", "province_0", "province_1", "省份", STRING_ENUM),
	// 流信息
	NewTagDescription("close_type", "close_type", "close_type", "流结束类型", INT_ENUM),
	NewTagDescription("flow_source", "flow_source", "flow_source", "流数据来源", INT),
	NewTagDescription("flow_id", "flow_id", "flow_id", "流日志ID", INT),
	NewTagDescription("tap_port", "tap_port", "tap_port", "采集位置标识", INT),
	NewTagDescription("tap_port_name", "tap_port_name", "tap_port_name", "采集位置名称", STRING),
	NewTagDescription("tap_port_type", "tap_port_type", "tap_port_type", "采集位置类型", INT_ENUM),
	NewTagDescription("tap_side", "tap_side", "tap_side", "路径统计位置", STRING_ENUM),
	NewTagDescription("l2_end", "l2_end_0", "l2_end_1", "二层边界", INT),
}
