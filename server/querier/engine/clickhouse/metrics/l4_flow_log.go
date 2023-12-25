/*
 * Copyright (c) 2023 Yunshan Networks
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

import (
	"fmt"
)

var DB_FIELD_NEW_FLOW = fmt.Sprintf(
	"if(is_new_flow=%d,1,0)", FLOW_LOG_IS_NEW_FLOW,
)
var DB_FIELD_CLOSED_FLOW = fmt.Sprintf(
	"if(close_type!=%d,1,0)", FLOW_LOG_CLOSE_TYPE_FORCED_REPORT,
)
var DB_FIELD_TCP_ESTABLISH_FAIL = fmt.Sprintf(
	"if(close_type in %s,1,0)", FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION,
)
var DB_FIELD_CLIENT_ESTABLISH_FAIL = fmt.Sprintf(
	"if(close_type in %s,1,0)", FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION_CLIENT,
)
var DB_FIELD_SERVER_ESTABLISH_FAIL = fmt.Sprintf(
	"if(close_type in %s,1,0)", FLOW_LOG_CLOSE_TYPE_ESTABLISH_EXCEPTION_SERVER,
)
var DB_FIELD_TCP_TRANSFER_FAIL = fmt.Sprintf(
	"if(close_type in %s,1,0)", FLOW_LOG_CLOSE_TYPE_EXCEPTION,
)
var DB_FIELD_TCP_RST_FAIL = fmt.Sprintf(
	"if(close_type in %s,1,0)", FLOW_LOG_CLOSE_TYPE_RST,
)
var DB_FIELD_CLIENT_SOURCE_PORT_REUSE = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_CLIENT_PORT_REUSE,
)
var DB_FIELD_CLIENT_SYN_REPEAT = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_CLIENT_SYN_REPEAT,
)
var DB_FIELD_CLIENT_ESTABLISH_OTHER_RST = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_CLIENT_ESTABLISH_RST,
)
var DB_FIELD_SERVER_RESET = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_SERVER_RST,
)
var DB_FIELD_SERVER_SYN_ACK_REPEAT = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_SERVER_SYNACK_REPEAT,
)
var DB_FIELD_SERVER_ESTABLISH_OTHER_RST = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_SERVER_ESTABLISH_RST,
)
var DB_FIELD_CLIENT_RST_FLOW = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_TCP_CLIENT_RST,
)
var DB_FIELD_SERVER_QUEUE_LACK = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_SERVER_QUEUE_LACK,
)
var DB_FIELD_SERVER_RST_FLOW = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_TCP_SERVER_RST,
)
var DB_FIELD_CLIENT_HALF_CLOSE_FLOW = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_CLIENT_HALF_CLOSE,
)
var DB_FIELD_SERVER_HALF_CLOSE_FLOW = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_SERVER_HALF_CLOSE,
)
var DB_FIELD_TCP_TIMEOUT = fmt.Sprintf(
	"if(close_type=%d,1,0)", FLOW_LOG_CLOSE_TYPE_TIMEOUT,
)

var L4_FLOW_LOG_METRICS = map[string]*Metrics{}

var L4_FLOW_LOG_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
	"byte":      NewReplaceMetrics("byte_tx+byte_rx", ""),
	"packet":    NewReplaceMetrics("packet_tx+packet_rx", ""),
	"l3_byte":   NewReplaceMetrics("l3_byte_tx+l3_byte_rx", ""),
	"l4_byte":   NewReplaceMetrics("l4_byte_tx+l4_byte_rx", ""),
	"bpp":       NewReplaceMetrics("(byte_tx+byte_rx)/(packet_tx+packet_rx)", "(packet_tx+packet_rx)>0"),
	"bpp_tx":    NewReplaceMetrics("byte_tx/packet_tx", "packet_tx>0"),
	"bpp_rx":    NewReplaceMetrics("byte_rx/packet_rx", "packet_rx>0"),

	"retrans":              NewReplaceMetrics("retrans_tx+retrans_rx", ""),
	"zero_win":             NewReplaceMetrics("zero_win_tx+zero_win_rx", ""),
	"retrans_ratio":        NewReplaceMetrics("(retrans_tx+retrans_rx)/(packet_tx+packet_rx)", "(packet_tx+packet_rx)>0"),
	"retrans_syn_ratio":    NewReplaceMetrics("retrans_syn/syn_count", "syn_count>0"),
	"retrans_synack_ratio": NewReplaceMetrics("retrans_synack/synack_count", "synack_count>0"),
	"retrans_tx_ratio":     NewReplaceMetrics("retrans_tx/packet_tx", "packet_tx>0"),
	"retrans_rx_ratio":     NewReplaceMetrics("retrans_rx/packet_rx", "packet_rx>0"),
	"zero_win_ratio":       NewReplaceMetrics("(zero_win_tx+zero_win_rx)/(packet_tx+packet_rx)", "(packet_tx+packet_rx)>0"),
	"zero_win_tx_ratio":    NewReplaceMetrics("zero_win_tx/packet_tx", "packet_tx>0"),
	"zero_win_rx_ratio":    NewReplaceMetrics("zero_win_rx/packet_rx", "packet_rx>0"),

	"new_flow":    NewReplaceMetrics(DB_FIELD_NEW_FLOW, ""),
	"closed_flow": NewReplaceMetrics(DB_FIELD_CLOSED_FLOW, ""),

	"tcp_establish_fail":          NewReplaceMetrics(DB_FIELD_TCP_ESTABLISH_FAIL, ""),
	"client_establish_fail":       NewReplaceMetrics(DB_FIELD_CLIENT_ESTABLISH_FAIL, ""),
	"server_establish_fail":       NewReplaceMetrics(DB_FIELD_SERVER_ESTABLISH_FAIL, ""),
	"tcp_establish_fail_ratio":    NewReplaceMetrics(DB_FIELD_TCP_ESTABLISH_FAIL+"/"+DB_FIELD_CLOSED_FLOW, DB_FIELD_CLOSED_FLOW+">0"),
	"client_establish_fail_ratio": NewReplaceMetrics(DB_FIELD_CLIENT_ESTABLISH_FAIL+"/"+DB_FIELD_CLOSED_FLOW, DB_FIELD_CLOSED_FLOW+">0"),
	"server_establish_fail_ratio": NewReplaceMetrics(DB_FIELD_SERVER_ESTABLISH_FAIL+"/"+DB_FIELD_CLOSED_FLOW, DB_FIELD_CLOSED_FLOW+">0"),

	"tcp_transfer_fail":          NewReplaceMetrics(DB_FIELD_TCP_TRANSFER_FAIL, ""),
	"tcp_transfer_fail_ratio":    NewReplaceMetrics(DB_FIELD_TCP_TRANSFER_FAIL+"/"+DB_FIELD_CLOSED_FLOW, DB_FIELD_CLOSED_FLOW+">0"),
	"tcp_rst_fail":               NewReplaceMetrics(DB_FIELD_TCP_RST_FAIL, ""),
	"tcp_rst_fail_ratio":         NewReplaceMetrics(DB_FIELD_TCP_RST_FAIL+"/"+DB_FIELD_CLOSED_FLOW, DB_FIELD_CLOSED_FLOW+">0"),
	"client_source_port_reuse":   NewReplaceMetrics(DB_FIELD_CLIENT_SOURCE_PORT_REUSE, ""),
	"client_syn_repeat":          NewReplaceMetrics(DB_FIELD_CLIENT_SYN_REPEAT, ""),
	"client_establish_other_rst": NewReplaceMetrics(DB_FIELD_CLIENT_ESTABLISH_OTHER_RST, ""),
	"server_reset":               NewReplaceMetrics(DB_FIELD_SERVER_RESET, ""),
	"server_syn_ack_repeat":      NewReplaceMetrics(DB_FIELD_SERVER_SYN_ACK_REPEAT, ""),
	"server_establish_other_rst": NewReplaceMetrics(DB_FIELD_SERVER_ESTABLISH_OTHER_RST, ""),
	"client_rst_flow":            NewReplaceMetrics(DB_FIELD_CLIENT_RST_FLOW, ""),
	"server_queue_lack":          NewReplaceMetrics(DB_FIELD_SERVER_QUEUE_LACK, ""),
	"server_rst_flow":            NewReplaceMetrics(DB_FIELD_SERVER_RST_FLOW, ""),
	"client_half_close_flow":     NewReplaceMetrics(DB_FIELD_CLIENT_HALF_CLOSE_FLOW, ""),
	"server_half_close_flow":     NewReplaceMetrics(DB_FIELD_SERVER_HALF_CLOSE_FLOW, ""),
	"tcp_timeout":                NewReplaceMetrics(DB_FIELD_TCP_TIMEOUT, ""),

	"srt": NewReplaceMetrics("srt_sum/srt_count", "").SetIsAgg(false),
	"art": NewReplaceMetrics("art_sum/art_count", "").SetIsAgg(false),
	"cit": NewReplaceMetrics("cit_sum/cit_count", "").SetIsAgg(false),
	"rrt": NewReplaceMetrics("rrt_sum/rrt_count", "").SetIsAgg(false),

	"l7_error":              NewReplaceMetrics("l7_client_error+l7_server_error", ""),
	"l7_error_ratio":        NewReplaceMetrics("l7_error/l7_response", "l7_response>0"),
	"l7_client_error_ratio": NewReplaceMetrics("l7_client_error/l7_response", "l7_response>0"),
	"l7_server_error_ratio": NewReplaceMetrics("l7_server_error/l7_response", "l7_response>0"),
}

func GetL4FlowLogMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return L4_FLOW_LOG_METRICS
}
