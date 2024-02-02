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

package ckissu

import (
	"fmt"
	"regexp"
	"strings"

	logging "github.com/op/go-logging"

	"database/sql"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/datasource"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("issu")

type Issu struct {
	cfg                *config.Config
	tableRenames       []*TableRename
	columnRenames      []*ColumnRename
	columnMods         []*ColumnMod
	columnAdds         []*ColumnAdd
	indexAdds          []*IndexAdd
	columnDrops        []*ColumnDrop
	modTTLs            []*TableModTTL
	datasourceInfo     map[string]*DatasourceInfo
	Connections        common.DBs
	Addrs              []string
	username, password string
	exit               bool
}

type TableRename struct {
	OldDb     string
	OldTables []string
	NewDb     string
	NewTables []string
}

type TableModTTL struct {
	Db     string
	Table  string
	NewTTL int
}

type ColumnRenames struct {
	Db              string
	Tables          []string
	OldColumnNames  []string
	CheckColumnType bool
	OldColumnType   string
	NewColumnNames  []string
	DropIndex       bool
	DropMvTable     bool
}

type ColumnRename struct {
	Db              string
	Table           string
	OldColumnName   string
	CheckColumnType bool
	OldColumnType   string
	NewColumnName   string
	DropIndex       bool
	DropMvTable     bool
}

type ColumnMod struct {
	Db            string
	Table         string
	ColumnName    string
	NewColumnType ckdb.ColumnType
	DropIndex     bool
}

type ColumnAdd struct {
	Db           string
	Table        string
	ColumnName   string
	ColumnType   ckdb.ColumnType
	DefaultValue string
}

type ColumnAdds struct {
	Dbs          []string
	Tables       []string
	ColumnNames  []string
	ColumnType   ckdb.ColumnType
	DefaultValue string
}

type ColumnDrop struct {
	Db         string
	Table      string
	ColumnName string
}

type ColumnDrops struct {
	Dbs         []string
	Tables      []string
	ColumnNames []string
}

type IndexAdds struct {
	Dbs         []string
	Tables      []string
	ColumnNames []string
	IndexType   ckdb.IndexType
}

type IndexAdd struct {
	Db         string
	Table      string
	ColumnName string
	IndexType  ckdb.IndexType
}

var TableRenames611 = []*TableRename{
	&TableRename{
		OldDb:     "vtap_acl",
		OldTables: []string{"1m_local"},
		NewDb:     "flow_metrics",
		NewTables: []string{"vtap_acl.1m_local"},
	},
	&TableRename{
		OldDb:     "vtap_flow_port",
		OldTables: []string{"1m_local", "1s_local"},
		NewDb:     "flow_metrics",
		NewTables: []string{"vtap_flow_port.1m_local", "vtap_flow_port.1s_local"},
	},
	&TableRename{
		OldDb:     "vtap_flow_edge_port",
		OldTables: []string{"1m_local", "1s_local"},
		NewDb:     "flow_metrics",
		NewTables: []string{"vtap_flow_edge_port.1m_local", "vtap_flow_edgeport.1s_local"},
	},
	&TableRename{
		OldDb:     "vtap_app_port",
		OldTables: []string{"1m_local", "1s_local"},
		NewDb:     "flow_metrics",
		NewTables: []string{"vtap_app_port.1m_local", "vtap_app_port.1s_local"},
	},
	&TableRename{
		OldDb:     "vtap_app_edge_port",
		OldTables: []string{"1m_local", "1s_local"},
		NewDb:     "flow_metrics",
		NewTables: []string{"vtap_app_edge_port.1m_local", "vtap_app_edge_port.1s_local"},
	},
}

var ColumnRename572 = []*ColumnRename{
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log",
		OldColumnName: "retans_tx",
		NewColumnName: "retrans_tx",
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log_local",
		OldColumnName: "retans_tx",
		NewColumnName: "retrans_tx",
	},
}

var ColumnAdd573 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"vtap_flow", "vtap_flow_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"service_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_edge", "vtap_flow_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"service_id_0", "service_id_1"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local", "l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local"},
		ColumnNames: []string{"service_id_0", "service_id_1"},
		ColumnType:  ckdb.UInt32,
	},
}

var ColumnAdd600 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_port", "vtap_flow_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"l7_client_error", "l7_server_error", "l7_timeout", "l7_error", "rrt_max"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_port", "vtap_flow_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"rrt_sum"},
		ColumnType:  ckdb.Float64,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_port", "vtap_flow_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"rrt_count", "l7_request", "l7_response", "tcp_transfer_fail", "tcp_rst_fail"},
		ColumnType:  ckdb.UInt64,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_edge_port", "vtap_flow_port", "vtap_app_port", "vtap_app_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"tap_port_type", "tunnel_type"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:          []string{"flow_log"},
		Tables:       []string{"l4_flow_log", "l4_flow_log_local", "l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local"},
		ColumnNames:  []string{"tap_side"},
		ColumnType:   ckdb.LowCardinalityString,
		DefaultValue: "'rest'",
	},
	&ColumnAdds{
		Dbs: []string{"flow_log"},
		Tables: []string{"l4_flow_log", "l4_flow_log_local", "l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local",
			"l7_mq_log", "l7_mq_log_local", "l7_sql_log", "l7_sql_log_local", "l7_nosql_log", "l7_nosql_log_local", "l7_rpc_log", "l7_rpc_log_local"},
		ColumnNames: []string{"tap_port_type", "tunnel_type"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"syn_seq", "syn_ack_seq", "l7_error", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1", "last_keepalive_seq", "last_keepalive_ack"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"is_new_flow"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local"},
		ColumnNames: []string{"req_tcp_seq", "resp_tcp_seq"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:          []string{"flow_log"},
		Tables:       []string{"l7_dns_log", "l7_dns_log_local"},
		ColumnNames:  []string{"protocol"},
		ColumnType:   ckdb.UInt8,
		DefaultValue: "17",
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local"},
		ColumnNames: []string{"status_code"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_http_log", "l7_http_log_local", "l7_dns_log", "l7_dns_log_local"},
		ColumnNames: []string{"exception_desc"},
		ColumnType:  ckdb.LowCardinalityString,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_http_log", "l7_http_log_local"},
		ColumnNames: []string{"response_length"},
		ColumnType:  ckdb.Int64Nullable,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_http_log", "l7_http_log_local"},
		ColumnNames: []string{"span_id"},
		ColumnType:  ckdb.String,
	},
}

var ColumnRename600 = []*ColumnRename{
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l7_http_log",
		OldColumnName: "status_code",
		NewColumnName: "answer_code",
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l7_http_log_local",
		OldColumnName: "status_code",
		NewColumnName: "answer_code",
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l7_http_log",
		OldColumnName: "content_length",
		NewColumnName: "request_length",
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l7_http_log_local",
		OldColumnName: "content_length",
		NewColumnName: "request_length",
	},
}

var ColumnAdd610 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"auto_instance_id_0", "auto_service_id_0", "auto_instance_id_1", "auto_service_id_1"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"auto_instance_type_0", "auto_service_type_0", "auto_instance_type_1", "auto_service_type_1", "status"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_flow_port.1m", "vtap_flow_port.1m_local", "vtap_flow_port.1s", "vtap_flow_port.1s_local", "vtap_app_port.1m", "vtap_app_port.1m_local", "vtap_app_port.1s", "vtap_app_port.1s_local"},
		ColumnNames: []string{"auto_instance_id", "auto_service_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_flow_port.1m", "vtap_flow_port.1m_local", "vtap_flow_port.1s", "vtap_flow_port.1s_local", "vtap_app_port.1m", "vtap_app_port.1m_local", "vtap_app_port.1s", "vtap_app_port.1s_local"},
		ColumnNames: []string{"auto_instance_type", "auto_service_type"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_flow_edge_port.1m", "vtap_flow_edge_port.1m_local", "vtap_flow_edge_port.1s", "vtap_flow_edge_port.1s_local", "vtap_app_edge_port.1m", "vtap_app_edge_port.1m_local", "vtap_app_edge_port.1s", "vtap_app_edge_port.1s_local"},
		ColumnNames: []string{"auto_instance_id_0", "auto_service_id_0", "auto_instance_id_1", "auto_service_id_1"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_flow_edge_port.1m", "vtap_flow_edge_port.1m_local", "vtap_flow_edge_port.1s", "vtap_flow_edge_port.1s_local", "vtap_app_edge_port.1m", "vtap_app_edge_port.1m_local", "vtap_app_edge_port.1s", "vtap_app_edge_port.1s_local"},
		ColumnNames: []string{"auto_instance_type_0", "auto_service_type_0", "auto_instance_type_1", "auto_service_type_1"},
		ColumnType:  ckdb.UInt8,
	},

	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"process_kname_0", "process_kname_1"},
		ColumnType:  ckdb.String,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"syscall_thread_0", "syscall_thread_1", "syscall_cap_seq_0", "syscall_cap_seq_1"},
		ColumnType:  ckdb.UInt32,
	},
}

var ColumnAdd611 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"attribute_names", "attribute_values"},
		ColumnType:  ckdb.ArrayString,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"l7_protocol_str", "service_name"},
		ColumnType:  ckdb.LowCardinalityString,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"span_kind"},
		ColumnType:  ckdb.UInt8Nullable,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"parent_span_id", "service_instance_id"},
		ColumnType:  ckdb.String,
	},
}

var ColumnMod611 = []*ColumnMod{
	&ColumnMod{
		Db:            "flow_log",
		Table:         "l7_flow_log",
		ColumnName:    "span_kind",
		NewColumnType: ckdb.UInt8Nullable,
		DropIndex:     false,
	},
	&ColumnMod{
		Db:            "flow_log",
		Table:         "l7_flow_log_local",
		ColumnName:    "span_kind",
		NewColumnType: ckdb.UInt8Nullable,
		DropIndex:     true,
	},
}

var u64ColumnNameAdd612 = []string{"syn_count", "synack_count", "retrans_syn", "retrans_synack", "cit_count"}
var u32ColumnNameAdd612 = []string{"cit_max"}
var f64ColumnNameAdd612 = []string{"cit_sum"}
var flowMetricsTableAdd612 = []string{
	"vtap_flow_port.1m", "vtap_flow_port.1m_local",
	"vtap_flow_port.1s", "vtap_flow_port.1s_local",
	"vtap_flow_edge_port.1m", "vtap_flow_edge_port.1m_local",
	"vtap_flow_edge_port.1s", "vtap_flow_edge_port.1s_local",
}

var ColumnAdd612 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"cit_max", "syn_count", "synack_count", "retrans_syn", "retrans_synack"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"cit_count"},
		ColumnType:  ckdb.UInt64,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"cit_sum"},
		ColumnType:  ckdb.Float64,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTableAdd612,
		ColumnNames: u64ColumnNameAdd612,
		ColumnType:  ckdb.UInt64,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTableAdd612,
		ColumnNames: u32ColumnNameAdd612,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTableAdd612,
		ColumnNames: f64ColumnNameAdd612,
		ColumnType:  ckdb.Float64,
	},
}

var ColumnAdd613 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"acl_gids"},
		ColumnType:  ckdb.ArrayUInt16,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"metrics_names"},
		ColumnType:  ckdb.ArrayString,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"metrics_values"},
		ColumnType:  ckdb.ArrayFloat64,
	},
}

var ColumnAdd615 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"endpoint"},
		ColumnType:  ckdb.String,
	},
}

var ColumnMod615 = []*ColumnMod{
	&ColumnMod{
		Db:            "flow_log",
		Table:         "l7_flow_log",
		ColumnName:    "response_code",
		NewColumnType: ckdb.Int32Nullable,
		DropIndex:     false,
	},
	&ColumnMod{
		Db:            "flow_log",
		Table:         "l7_flow_log_local",
		ColumnName:    "response_code",
		NewColumnType: ckdb.Int32Nullable,
		DropIndex:     false,
	},
}

var ColumnRename618 = []*ColumnRename{
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log_local",
		OldColumnName: "flow_source",
		NewColumnName: "signal_source",
		DropIndex:     true,
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log",
		OldColumnName: "flow_source",
		NewColumnName: "signal_source",
	},
}

var ColumnAdd618 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"signal_source"},
		ColumnType:  ckdb.UInt16,
	},
}

var u8ColumnNameAdd620 = []string{"nat_source"}
var u32ColumnNameAdd620 = []string{"gprocess_id"}
var u32ColumnNameEdgeAdd620 = []string{"gprocess_id_0", "gprocess_id_1"}
var flowMetricsEdgeTables = []string{
	"vtap_flow_edge_port.1m", "vtap_flow_edge_port.1m_local",
	"vtap_flow_edge_port.1s", "vtap_flow_edge_port.1s_local",
	"vtap_app_edge_port.1m", "vtap_app_edge_port.1m_local",
	"vtap_app_edge_port.1s", "vtap_app_edge_port.1s_local",
}
var flowMetricsTables = []string{
	"vtap_flow_port.1m", "vtap_flow_port.1m_local",
	"vtap_flow_port.1s", "vtap_flow_port.1s_local",
	"vtap_app_port.1m", "vtap_app_port.1m_local",
	"vtap_app_port.1s", "vtap_app_port.1s_local",
}

var ColumnAdd620 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsEdgeTables,
		ColumnNames: u8ColumnNameAdd620,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log", "l7_flow_log_local"},
		ColumnNames: u8ColumnNameAdd620,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"nat_real_ip4_0", "nat_real_ip4_1"},
		ColumnType:  ckdb.IPv4,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"nat_real_port_0", "nat_real_port_1"},
		ColumnType:  ckdb.UInt16,
	},

	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTables,
		ColumnNames: u32ColumnNameAdd620,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsEdgeTables,
		ColumnNames: u32ColumnNameEdgeAdd620,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log", "l7_flow_log_local"},
		ColumnNames: u32ColumnNameEdgeAdd620,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_packet", "l4_packet_local"},
		ColumnNames: []string{"packet_batch"},
		ColumnType:  ckdb.String,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_packet", "l7_packet_local"},
		ColumnNames: []string{"pcap_batch"},
		ColumnType:  ckdb.String,
	},
}

var ColumnRename620 = []*ColumnRename{
	&ColumnRename{
		Db:              "flow_log",
		Table:           "l7_packet",
		OldColumnName:   "pcap_batch",
		CheckColumnType: true,
		OldColumnType:   ckdb.ArrayUInt8.String(),
		NewColumnName:   "pcap_batch_bak",
	},
	&ColumnRename{
		Db:              "flow_log",
		Table:           "l7_packet_local",
		OldColumnName:   "pcap_batch",
		CheckColumnType: true,
		OldColumnType:   ckdb.ArrayUInt8.String(),
		NewColumnName:   "pcap_batch_bak",
	},
	&ColumnRename{
		Db:              "flow_log",
		Table:           "l4_packet",
		OldColumnName:   "packet_batch",
		CheckColumnType: true,
		OldColumnType:   ckdb.ArrayUInt8.String(),
		NewColumnName:   "packet_batch_bak",
	},
	&ColumnRename{
		Db:              "flow_log",
		Table:           "l4_packet_local",
		OldColumnName:   "packet_batch",
		CheckColumnType: true,
		OldColumnType:   ckdb.ArrayUInt8.String(),
		NewColumnName:   "packet_batch_bak",
	},
}

var u8OldColumnName623 = []string{"resource_gl0_type", "resource_gl2_type"}
var u8NewColumnName623 = []string{"auto_instance_type", "auto_service_type"}
var u32OldColumnName623 = []string{"resource_gl0_id", "resource_gl2_id"}
var u32NewColumnName623 = []string{"auto_instance_id", "auto_service_id"}

var u8OldColumnEdgeName623 = []string{"resource_gl0_type_0", "resource_gl0_type_1", "resource_gl2_type_0", "resource_gl2_type_1"}
var u8NewColumnEdgeName623 = []string{"auto_instance_type_0", "auto_instance_type_1", "auto_service_type_0", "auto_service_type_1"}
var u32OldColumnEdgeName623 = []string{"resource_gl0_id_0", "resource_gl0_id_1", "resource_gl2_id_0", "resource_gl2_id_1"}
var u32NewColumnEdgeName623 = []string{"auto_instance_id_0", "auto_instance_id_1", "auto_service_id_0", "auto_service_id_1"}
var flowLogTables = []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log", "l7_flow_log_local"}
var vtapAppTables = []string{
	"vtap_app_port.1m", "vtap_app_port.1m_local",
	"vtap_app_port.1s", "vtap_app_port.1s_local",
	"vtap_app_edge_port.1m", "vtap_app_edge_port.1m_local",
	"vtap_app_edge_port.1s", "vtap_app_edge_port.1s_local",
}

var ColumnAdd623 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTables,
		ColumnNames: []string{"signal_source"},
		ColumnType:  ckdb.UInt16,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsEdgeTables,
		ColumnNames: []string{"signal_source"},
		ColumnType:  ckdb.UInt16,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      vtapAppTables,
		ColumnNames: []string{"app_service"},
		ColumnType:  ckdb.LowCardinalityString,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      vtapAppTables,
		ColumnNames: []string{"app_instance", "endpoint"},
		ColumnType:  ckdb.String,
	},
}

var ColumnRename623 = []*ColumnRenames{
	&ColumnRenames{
		Db:             "flow_log",
		Tables:         []string{"l7_flow_log", "l7_flow_log_local"},
		OldColumnNames: []string{"service_name", "service_instance_id"},
		NewColumnNames: []string{"app_service", "app_instance"},
	},
	&ColumnRenames{
		Db:             "flow_log",
		Tables:         flowLogTables,
		OldColumnNames: u8OldColumnEdgeName623,
		NewColumnNames: u8NewColumnEdgeName623,
		DropIndex:      true,
	},
	&ColumnRenames{
		Db:             "flow_log",
		Tables:         flowLogTables,
		OldColumnNames: u32OldColumnEdgeName623,
		NewColumnNames: u32NewColumnEdgeName623,
		DropIndex:      true,
	},
	&ColumnRenames{
		Db:             "flow_metrics",
		Tables:         flowMetricsTables,
		OldColumnNames: u8OldColumnName623,
		NewColumnNames: u8NewColumnName623,
		DropIndex:      true,
		DropMvTable:    true,
	},
	&ColumnRenames{
		Db:             "flow_metrics",
		Tables:         flowMetricsTables,
		OldColumnNames: u32OldColumnName623,
		NewColumnNames: u32NewColumnName623,
		DropIndex:      true,
		DropMvTable:    true,
	},
	&ColumnRenames{
		Db:             "flow_metrics",
		Tables:         flowMetricsEdgeTables,
		OldColumnNames: u8OldColumnEdgeName623,
		NewColumnNames: u8NewColumnEdgeName623,
		DropIndex:      true,
		DropMvTable:    true,
	},
	&ColumnRenames{
		Db:             "flow_metrics",
		Tables:         flowMetricsEdgeTables,
		OldColumnNames: u32OldColumnEdgeName623,
		NewColumnNames: u32NewColumnEdgeName623,
		DropIndex:      true,
		DropMvTable:    true,
	},
	&ColumnRenames{
		Db:             "ext_metrics",
		Tables:         []string{"metrics", "metrics_local"},
		OldColumnNames: u8OldColumnName623,
		NewColumnNames: u8NewColumnName623,
		DropIndex:      true,
	},
	&ColumnRenames{
		Db:             "ext_metrics",
		Tables:         []string{"metrics", "metrics_local"},
		OldColumnNames: u32OldColumnName623,
		NewColumnNames: u32NewColumnName623,
		DropIndex:      true,
	},
}

var u8ColumnNameAdd625 = []string{"direction_score"}
var ColumnAdd625 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTables,
		ColumnNames: u8ColumnNameAdd625,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsEdgeTables,
		ColumnNames: u8ColumnNameAdd625,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      flowLogTables,
		ColumnNames: u8ColumnNameAdd625,
		ColumnType:  ckdb.UInt8,
	},
}

var u8ColumnProfileNameAdd626 = []string{"is_ipv4"}
var u16ColumnProfileNameAdd626 = []string{"subnet_id"}
var profileTables = []string{"in_process", "in_process_local"}
var ColumnAdd626 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      profileTables,
		ColumnNames: u8ColumnProfileNameAdd626,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      profileTables,
		ColumnNames: u16ColumnProfileNameAdd626,
		ColumnType:  ckdb.UInt16,
	},
	&ColumnAdds{
		Dbs:         []string{"ext_metrics"},
		Tables:      []string{"metrics", "metrics_local"},
		ColumnNames: []string{"gprocess_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_packet", "l4_packet_local", "l7_packet", "l7_packet_local"},
		ColumnNames: []string{"start_time"},
		ColumnType:  ckdb.DateTime64us,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_packet", "l7_packet_local"},
		ColumnNames: []string{"acl_gids"},
		ColumnType:  ckdb.ArrayUInt16,
	},
}

var TableRenames626 = []*TableRename{
	&TableRename{
		OldDb:     "event",
		OldTables: []string{"event", "event_local"},
		NewDb:     "event",
		NewTables: []string{"event_v625", "event_local_v625"},
	},
}

var ColumnRenames626 = []*ColumnRenames{
	&ColumnRenames{
		Db:             "flow_log",
		Tables:         []string{"l7_packet", "l7_packet_local"},
		OldColumnNames: []string{"pcap_count", "pcap_batch"},
		NewColumnNames: []string{"packet_count", "packet_batch"},
	},
}

var u32ColumnNameAdd633 = []string{"netns_id"}
var u32ColumnNameEdgeAdd633 = []string{"netns_id_0", "netns_id_1"}
var u8ColumnNameAdd633 = []string{"tag_source"}
var u8ColumnNameEdgeAdd633 = []string{"tag_source_0", "tag_source_1"}
var vtapAppPortTables = []string{
	"vtap_app_port.1m", "vtap_app_port.1m_local",
	"vtap_app_port.1s", "vtap_app_port.1s_local",
}
var vtapAppEdgePortTables = []string{
	"vtap_app_edge_port.1m", "vtap_app_edge_port.1m_local",
	"vtap_app_edge_port.1s", "vtap_app_edge_port.1s_local",
}
var l7FlowLogTables = []string{"l7_flow_log", "l7_flow_log_local"}

var ColumnAdd633 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_flow_port.1m", "vtap_flow_port.1m_local", "vtap_flow_port.1s", "vtap_flow_port.1s_local", "vtap_app_port.1m", "vtap_app_port.1m_local", "vtap_app_port.1s", "vtap_app_port.1s_local"},
		ColumnNames: []string{"role"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"event"},
		Tables:      []string{"event", "event_local", "perf_event", "perf_event_local"},
		ColumnNames: u32ColumnNameAdd633,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      vtapAppPortTables,
		ColumnNames: u32ColumnNameAdd633,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      vtapAppEdgePortTables,
		ColumnNames: u32ColumnNameEdgeAdd633,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      l7FlowLogTables,
		ColumnNames: u32ColumnNameEdgeAdd633,
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsTables,
		ColumnNames: u8ColumnNameAdd633,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      flowMetricsEdgeTables,
		ColumnNames: u8ColumnNameEdgeAdd633,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log", "l7_flow_log_local"},
		ColumnNames: u8ColumnNameEdgeAdd633,
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"x_request_id_0", "x_request_id_1"},
		ColumnType:  ckdb.String,
	},
	&ColumnAdds{
		Dbs:         []string{"event"},
		Tables:      []string{"alarm_event", "alarm_event_local"},
		ColumnNames: []string{"alarm_target"},
		ColumnType:  ckdb.LowCardinalityString,
	},
	&ColumnAdds{
		Dbs:         []string{"event"},
		Tables:      []string{"alarm_event", "alarm_event_local"},
		ColumnNames: []string{"region_id"},
		ColumnType:  ckdb.UInt16,
	},
	&ColumnAdds{
		Dbs:         []string{"event"},
		Tables:      []string{"alarm_event", "alarm_event_local"},
		ColumnNames: []string{"policy_query_url", "policy_query_conditions", "policy_threshold_critical", "policy_threshold_error", "policy_threshold_warning"},
		ColumnType:  ckdb.String,
	},
}

var ColumnAdd635 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"compression_algo"},
		ColumnType:  ckdb.LowCardinalityString,
	},
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"process_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"process_start_time"},
		ColumnType:  ckdb.DateTime64,
	},
	&ColumnAdds{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"netns_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"l7_parse_failed"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"event"},
		Tables:      []string{"alarm_event", "alarm_event_local"},
		ColumnNames: []string{"user_id"},
		ColumnType:  ckdb.UInt32,
	},
}

var ColumnDrops635 = []*ColumnDrops{
	&ColumnDrops{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"profile_node_id", "profile_parent_node_id"},
	},
}

var IndexAdd63 = []*IndexAdds{
	&IndexAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log_local"},
		ColumnNames: []string{"trace_id", "x_request_id_0", "x_request_id_1", "request_resource", "request_domain", "endpoint"},
		IndexType:   ckdb.IndexBloomfilter,
	},
	&IndexAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log_local"},
		ColumnNames: []string{"_id"},
		IndexType:   ckdb.IndexMinmax,
	},
}

var TableModTTL64 = []*TableModTTL{
	&TableModTTL{
		Db:     "flow_metrics",
		Table:  "vtap_acl.1m_local",
		NewTTL: 168,
	},
}

var ColumnAdd65 = []*ColumnAdds{
	&ColumnAdds{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"vtap_acl.1m", "vtap_acl.1m_local"},
		ColumnNames: []string{"tunnel_ip_id"},
		ColumnType:  ckdb.UInt16,
	},
}

func getTables(connect *sql.DB, db, tableName string) ([]string, error) {
	sql := fmt.Sprintf("SHOW TABLES IN %s", db)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	tables := []string{}
	var table string
	for rows.Next() {
		err := rows.Scan(&table)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(table, tableName) ||
			len(tableName) == 0 {
			tables = append(tables, table)
		}
	}
	return tables, nil
}

func getMvTables(connect *sql.DB, db, tableName string) ([]string, error) {
	tables, err := getTables(connect, db, tableName)
	if err != nil {
		return nil, err
	}
	mvTables := []string{}
	for _, table := range tables {
		if strings.HasSuffix(table, "_mv") {
			mvTables = append(mvTables, table)
		}
	}
	return mvTables, nil
}

type DatasourceInfo struct {
	db         string
	name       string
	baseTable  string
	summable   string
	unsummable string
	interval   ckdb.TimeFuncType
}

func (i *Issu) getDatasourceInfo(connect *sql.DB, db, mvTableName string) (*DatasourceInfo, error) {
	if info, ok := i.datasourceInfo[db+mvTableName]; ok {
		return info, nil
	}
	sql := fmt.Sprintf("SHOW CREATE TABLE %s.`%s`", db, mvTableName)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	var createSql string
	for rows.Next() {
		err := rows.Scan(&createSql)
		if err != nil {
			return nil, err
		}
	}
	log.Infof("getDatasourceInfo sql: %s createSql: %s ", sql, createSql)
	var summable, unsummable, interval, baseTable string
	var matchs [4]string
	// 匹配 `packet_tx__agg` AggregateFunction(sum, UInt64), 中的 'sum' 为可累加聚合的方法
	summableReg := regexp.MustCompile("`packet_tx__agg` AggregateFunction.([a-z]+)")
	// 匹配 `rtt_sum__agg` AggregateFunction(avg, Float64), 中的 'avg' 为非可累加聚合的方法
	unsummableReg := regexp.MustCompile("`rtt_sum__agg` AggregateFunction.([a-zA-Z]+)")
	if strings.HasPrefix(mvTableName, "vtap_app") {
		summableReg = regexp.MustCompile("`request__agg` AggregateFunction.([a-z]+)")
		unsummableReg = regexp.MustCompile("`rrt_sum__agg` AggregateFunction.([a-zA-Z]+)")
	}
	// 匹配 toStartOfHour(time) AS time, 中的 'Hour' 为聚合时长
	intervalReg := regexp.MustCompile("toStartOf([a-zA-Z]+)")
	// 匹配 FROM vtap_flow.`1m_local` 中的'1m' 为原始数据源
	baseTableReg := regexp.MustCompile("FROM .*.`(.*)_local`")

	for i, reg := range []*regexp.Regexp{summableReg, unsummableReg, intervalReg, baseTableReg} {
		submatchs := reg.FindStringSubmatch(createSql)
		if len(submatchs) > 1 {
			matchs[i] = submatchs[1]
		} else {
			return nil, fmt.Errorf("parase %d failed", i)
		}
	}
	summable, unsummable, interval, baseTable = matchs[0], matchs[1], matchs[2], matchs[3]
	if unsummable == "argMax" {
		unsummable = "max"
	} else if unsummable == "argMin" {
		unsummable = "min"
	}
	log.Info("get summable, unsummable, interval, baseTable:", summable, unsummable, interval, baseTable)

	intervalTime := ckdb.TimeFuncHour
	if interval == "Day" {
		intervalTime = ckdb.TimeFuncDay
	} else if interval == "Hour" {
		intervalTime = ckdb.TimeFuncHour
	} else {
		return nil, fmt.Errorf("invalid interval %s", interval)
	}

	return &DatasourceInfo{
		db:         db,
		baseTable:  baseTable,
		name:       mvTableName[:len(mvTableName)-len("_mv")],
		summable:   summable,
		unsummable: unsummable,
		interval:   intervalTime,
	}, nil
}

// 找出自定义数据源和参数
func (i *Issu) getUserDefinedDatasourceInfos(connect *sql.DB, db, tableName string) ([]*DatasourceInfo, error) {
	tables, err := getTables(connect, db, tableName)
	if err != nil {
		log.Info(err)
		return nil, nil
	}

	aggTables := []string{}
	aggSuffix := "_agg"
	for _, t := range tables {
		if strings.HasSuffix(t, aggSuffix) {
			aggTables = append(aggTables, t[:len(t)-len(aggSuffix)])
		}
	}

	dSInfos := []*DatasourceInfo{}
	for _, name := range aggTables {
		ds, err := i.getDatasourceInfo(connect, db, name+"_mv")
		if err != nil {
			return nil, err
		}
		dSInfos = append(dSInfos, ds)
	}

	return dSInfos, nil
}

func (i *Issu) addColumnDatasource(connect *sql.DB, d *DatasourceInfo, isEdgeTable bool, isAppTable bool) ([]*ColumnAdd, error) {
	// mod table agg, global
	dones := []*ColumnAdd{}

	columnAdds := []*ColumnAdd{}
	var columnAddss612 = []*ColumnAdds{
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: u32ColumnNameAdd612,
			ColumnType:  ckdb.UInt32,
		},
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: u64ColumnNameAdd612,
			ColumnType:  ckdb.UInt64,
		},
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: f64ColumnNameAdd612,
			ColumnType:  ckdb.Float64,
		},
	}

	var columnAddss620 = []*ColumnAdds{
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: u8ColumnNameAdd620,
			ColumnType:  ckdb.UInt8,
		},
	}

	var columnAddss623 = []*ColumnAdds{
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: []string{"signal_source"},
			ColumnType:  ckdb.UInt16,
		},
	}

	if isAppTable {
		columnAddss623 = append(columnAddss623, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: []string{"app_service"},
				ColumnType:  ckdb.LowCardinalityString,
			},
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: []string{"app_instance", "endpoint"},
				ColumnType:  ckdb.String,
			},
		}...)
	}

	if isEdgeTable {
		columnAddss620 = append(columnAddss620, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u32ColumnNameEdgeAdd620,
				ColumnType:  ckdb.UInt32,
			},
		}...)
		columnAddss623 = append(columnAddss623, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u8NewColumnEdgeName623,
				ColumnType:  ckdb.UInt8,
			},
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u32NewColumnEdgeName623,
				ColumnType:  ckdb.UInt32,
			},
		}...)
	} else {
		columnAddss620 = append(columnAddss620, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u32ColumnNameAdd620,
				ColumnType:  ckdb.UInt32,
			},
		}...)
		columnAddss623 = append(columnAddss623, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u8NewColumnName623,
				ColumnType:  ckdb.UInt8,
			},
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: u32NewColumnName623,
				ColumnType:  ckdb.UInt32,
			},
		}...)
	}

	var columnAddss625 = []*ColumnAdds{
		&ColumnAdds{
			Dbs:         []string{d.db},
			Tables:      []string{d.name, d.name + "_agg"},
			ColumnNames: u8ColumnNameAdd625,
			ColumnType:  ckdb.UInt8,
		},
	}

	columnAddss633 := []*ColumnAdds{}
	if !isEdgeTable {
		columnAddss633 = append(columnAddss633, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: []string{"role", "tag_source"},
				ColumnType:  ckdb.UInt8,
			},
		}...)

	} else {
		columnAddss633 = append(columnAddss633, []*ColumnAdds{
			&ColumnAdds{
				Dbs:         []string{d.db},
				Tables:      []string{d.name, d.name + "_agg"},
				ColumnNames: []string{"tag_source_0", "tag_source_1"},
				ColumnType:  ckdb.UInt8,
			},
		}...)
	}

	if isAppTable {
		if isEdgeTable {
			columnAddss633 = append(columnAddss633, []*ColumnAdds{
				&ColumnAdds{
					Dbs:         []string{d.db},
					Tables:      []string{d.name, d.name + "_agg"},
					ColumnNames: u32ColumnNameEdgeAdd633,
					ColumnType:  ckdb.UInt32,
				},
			}...)
		} else {
			columnAddss633 = append(columnAddss633, []*ColumnAdds{
				&ColumnAdds{
					Dbs:         []string{d.db},
					Tables:      []string{d.name, d.name + "_agg"},
					ColumnNames: u32ColumnNameAdd633,
					ColumnType:  ckdb.UInt32,
				},
			}...)
		}
	}

	for _, version := range [][]*ColumnAdds{columnAddss612, columnAddss620, columnAddss623, columnAddss625, columnAddss633} {
		for _, addrs := range version {
			columnAdds = append(columnAdds, getColumnAdds(addrs)...)
		}
	}

	for _, addColumn := range columnAdds {
		version, err := i.getTableVersion(connect, addColumn.Db, addColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.addColumn(connect, addColumn); err != nil {
			return dones, err
		}
		dones = append(dones, addColumn)
	}

	if len(dones) == 0 {
		log.Infof("datasource db(%s) table(%s) already updated.", d.db, d.name)
		return nil, nil
	}

	// drop table mv
	sql := fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`", d.db, d.name+"_mv")
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		return nil, err
	}

	lastUnderlineIndex := strings.LastIndex(d.name, ".")
	if lastUnderlineIndex < 0 {
		return nil, fmt.Errorf("invalid table name %s", d.name)
	}
	dstTableName := d.name[lastUnderlineIndex+1:]
	rawTable := zerodoc.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, ckdb.DF_CLUSTER, ckdb.DF_STORAGE_POLICY, 7, 1, 7, 1, i.cfg.GetCKDBColdStorages())[zerodoc.MetricsTableNameToID(d.baseTable)]
	// create table mv
	createMvSql := datasource.MakeMVTableCreateSQL(
		rawTable, dstTableName,
		d.summable, d.unsummable, d.interval)
	log.Info(createMvSql)
	_, err = connect.Exec(createMvSql)
	if err != nil {
		return nil, err
	}

	// drop table local
	sql = fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`", d.db, d.name+"_local")
	log.Info(sql)
	_, err = connect.Exec(sql)
	if err != nil {
		return nil, err
	}

	// create table local
	createLocalSql := datasource.MakeCreateTableLocal(
		rawTable, dstTableName,
		d.summable, d.unsummable)
	log.Info(createLocalSql)
	_, err = connect.Exec(createLocalSql)
	if err != nil {
		return nil, err

	}
	return dones, nil
}

func NewCKIssu(cfg *config.Config) (*Issu, error) {
	i := &Issu{
		cfg:            cfg,
		Addrs:          cfg.CKDB.ActualAddrs,
		username:       cfg.CKDBAuth.Username,
		password:       cfg.CKDBAuth.Password,
		datasourceInfo: make(map[string]*DatasourceInfo),
	}

	allVersionAdds := [][]*ColumnAdds{ColumnAdd610, ColumnAdd611, ColumnAdd612, ColumnAdd613, ColumnAdd615, ColumnAdd618, ColumnAdd620, ColumnAdd623, ColumnAdd625, ColumnAdd626, ColumnAdd633, ColumnAdd635, ColumnAdd65}
	i.columnAdds = []*ColumnAdd{}
	for _, versionAdd := range allVersionAdds {
		for _, adds := range versionAdd {
			i.columnAdds = append(i.columnAdds, getColumnAdds(adds)...)
		}
	}

	for _, v := range [][]*IndexAdd{getIndexAdds(IndexAdd63)} {
		i.indexAdds = append(i.indexAdds, v...)
	}

	for _, v := range [][]*ColumnMod{ColumnMod611, ColumnMod615} {
		i.columnMods = append(i.columnMods, v...)
	}

	for _, v := range [][]*ColumnRename{ColumnRename618, ColumnRename620, getColumnRenames(ColumnRename623), getColumnRenames(ColumnRenames626)} {
		i.columnRenames = append(i.columnRenames, v...)
	}

	for _, v := range [][]*ColumnDrop{getColumnDrops(ColumnDrops635)} {
		i.columnDrops = append(i.columnDrops, v...)
	}

	for _, v := range [][]*TableModTTL{TableModTTL64} {
		i.modTTLs = append(i.modTTLs, v...)
	}

	var err error
	i.Connections, err = common.NewCKConnections(i.Addrs, i.username, i.password)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (i *Issu) RunRenameTable(ds *datasource.DatasourceManager) error {
	i.tableRenames = TableRenames611
	for _, connection := range i.Connections {
		oldVersion, err := i.getTableVersion(connection, "flow_log", "l4_flow_log_local")
		if err != nil {
			return err
		}
		if strings.Compare(oldVersion, "v6.1.1") >= 0 || oldVersion == "" {
			continue
		}
		for _, tableRename := range i.tableRenames {
			if err := i.renameTable(connection, tableRename); err != nil {
				return err
			}
		}
		if err := i.renameUserDefineDatasource(connection, ds); err != nil {
			log.Warning(err)
		}
	}
	i.tableRenames = TableRenames626
	for _, connection := range i.Connections {
		oldVersion, err := i.getTableVersion(connection, "event", "event_local")
		if err != nil {
			return err
		}
		if strings.Compare(oldVersion, "v6.2.6.2") >= 0 {
			continue
		}
		for _, tableRename := range i.tableRenames {
			if err := i.renameTable(connection, tableRename); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Issu) renameTable(connect *sql.DB, c *TableRename) error {
	for i := range c.OldTables {
		createDb := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", c.NewDb)
		_, err := connect.Exec(createDb)
		if err != nil {
			log.Error(err)
			return err
		}

		// RENAME TABLE vtap_acl.1m TO flow_metrics."vtap_acl.1m";
		sql := fmt.Sprintf("RENAME TABLE %s.%s to %s.\"%s\"",
			c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i])
		log.Info("rename table: ", sql)
		_, err = connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "doesn't exist") {
				log.Infof("table: %s.%s rename to table: %s.\"%s\" error: %s", c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i], err)
				continue
			} else if strings.Contains(err.Error(), "already exists") {
				log.Infof("table: %s.%s rename to table: %s.\"%s\" error: %s", c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i], err)
				continue
			}
			log.Error(err)
			return err
		}
	}
	return nil
}

func (i *Issu) addColumn(connect *sql.DB, c *ColumnAdd) error {
	defaultValue := ""
	if len(c.DefaultValue) > 0 {
		defaultValue = fmt.Sprintf("default %s", c.DefaultValue)
	}
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN %s %s %s",
		c.Db, c.Table, c.ColumnName, c.ColumnType, defaultValue)
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经增加，需要跳过该错误
		if strings.Contains(err.Error(), "column with this name already exists") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
			// The 'metrics/metrics_local' table is created after receiving the ext_metric data. If the table field is modified just after the system starts, it will cause an error. Ignore it
		} else if strings.Contains(err.Error(), "Table ext_metrics.metrics doesn't exist") || strings.Contains(err.Error(), "Table ext_metrics.metrics_local doesn't exist") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) addIndex(connect *sql.DB, c *IndexAdd) error {
	indexName := c.ColumnName + "_idx"
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` ADD INDEX %s %s TYPE %s GRANULARITY 3",
		c.Db, c.Table, indexName, c.ColumnName, c.IndexType)
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// if it already exists, you need to skip it
		if strings.Contains(err.Error(), "index with this name already exists") {
			log.Infof("index db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
			// The 'metrics/metrics_local' table is created after receiving the ext_metric data. If the table field is modified just after the system starts, it will cause an error. Ignore it
		} else if strings.Contains(err.Error(), "Table ext_metrics.metrics doesn't exist") || strings.Contains(err.Error(), "Table ext_metrics.metrics_local doesn't exist") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
		}
		log.Error(err)
		return err
	} else {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` MATERIALIZE INDEX %s",
			c.Db, c.Table, indexName)
		log.Info(sql)
		connect.Exec(sql)
	}
	return nil
}

func (i *Issu) getColumnType(connect *sql.DB, db, table, columnName string) (string, error) {
	sql := fmt.Sprintf("SELECT type FROM system.columns WHERE database='%s' AND table='%s' AND name='%s'",
		db, table, columnName)
	rows, err := connect.Query(sql)
	if err != nil {
		return "", err
	}
	var ctype string
	for rows.Next() {
		err := rows.Scan(&ctype)
		if err != nil {
			return "", err
		}
	}
	return ctype, nil
}

func (i *Issu) saveDatasourceInfo(connect *sql.DB, db, mvTable string) {
	if info, err := i.getDatasourceInfo(connect, db, mvTable); err == nil {
		log.Infof("save datasource info: %+v", *info)
		i.datasourceInfo[db+mvTable] = info
	}
}

func (i *Issu) renameColumn(connect *sql.DB, cr *ColumnRename) error {
	if cr.CheckColumnType {
		columnType, err := i.getColumnType(connect, cr.Db, cr.Table, cr.OldColumnName)
		if err != nil {
			log.Error(err)
			return err
		}
		if columnType != cr.OldColumnType {
			return nil
		}
	}
	if cr.DropIndex {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx",
			cr.Db, cr.Table, cr.OldColumnName)
		log.Info("drop index: ", sql)
		_, err := connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "Cannot find index") {
				log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			} else if strings.Contains(err.Error(), "is not supported by storage Distributed") {
				log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
			} else if strings.Contains(err.Error(), "doesn't exist") {
				log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
			} else {
				log.Errorf("sql: %s, error: %s", sql, err)
				return err
			}
		}
	}

	if cr.DropMvTable {
		mvTables, err := getMvTables(connect, cr.Db, strings.Split(cr.Table, ".")[0])
		if err != nil {
			log.Error(err)
			return err
		}
		for _, mvTable := range mvTables {
			i.saveDatasourceInfo(connect, cr.Db, mvTable)
			sql := fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`",
				cr.Db, mvTable)
			log.Info("drop mv talbe: ", sql)
			_, err := connect.Exec(sql)
			if err != nil {
				log.Error(err)
				return err
			}
		}
	}

	// ALTER TABLE flow_log.l4_flow_log  RENAME COLUMN retan_tx TO retran_tx
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` RENAME COLUMN IF EXISTS %s to %s",
		cr.Db, cr.Table, cr.OldColumnName, cr.NewColumnName)
	log.Info("rename column: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经修改过，就会报错不存在column，需要跳过该错误
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `retan_tx` to rename.
		if strings.Contains(err.Error(), "Cannot find column") ||
			strings.Contains(err.Error(), "column with this name already exists") {
			log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			return nil
		} else if strings.Contains(err.Error(), "doesn't exist") {
			log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) modColumn(connect *sql.DB, cm *ColumnMod) error {
	if cm.DropIndex {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx",
			cm.Db, cm.Table, cm.ColumnName)
		log.Info("drop index: ", sql)
		_, err := connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "Cannot find index") {
				log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			} else if strings.Contains(err.Error(), "'DROP_INDEX' is not supported by storage Distributed") {
				log.Infof("db: %s, table: %s info: %s", cm.Db, cm.Table, err)
			} else {
				log.Error(err)
				return err
			}
		}
	}
	// ALTER TABLE flow_log.l7_flow_log  MODIFY COLUMN span_kind Nullable(UInt8);
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY COLUMN %s %s",
		cm.Db, cm.Table, cm.ColumnName, cm.NewColumnType)
	log.Info("modify column: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		//If cannot find column, you need to skip the error
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `span_kind` to modify.
		if strings.Contains(err.Error(), "Cannot find column") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) dropColumn(connect *sql.DB, cm *ColumnDrop) error {
	// drop index first
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx", cm.Db, cm.Table, cm.ColumnName)
	log.Info("drop index: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		if strings.Contains(err.Error(), "Cannot find index") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
		} else if strings.Contains(err.Error(), "'DROP_INDEX' is not supported by storage Distributed") {
			log.Infof("db: %s, table: %s info: %s", cm.Db, cm.Table, err)
		} else {
			log.Error(err)
			return err
		}
	}

	// then drop column
	sql = fmt.Sprintf("ALTER TABLE %s.`%s` DROP COLUMN %s", cm.Db, cm.Table, cm.ColumnName)
	log.Info("drop column: ", sql)
	_, err = connect.Exec(sql)
	if err != nil {
		//If cannot find column, you need to skip the error
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `span_kind` to modify.
		if strings.Contains(err.Error(), "Cannot find column") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func getColumnDrops(columnDrops []*ColumnDrops) []*ColumnDrop {
	drops := []*ColumnDrop{}
	for _, columnDrop := range columnDrops {
		for _, d := range columnDrop.Dbs {
			for _, table := range columnDrop.Tables {
				for _, name := range columnDrop.ColumnNames {
					drops = append(drops, &ColumnDrop{
						Db:         d,
						Table:      table,
						ColumnName: name,
					})
				}
			}
		}
	}
	return drops
}

func (i *Issu) getTableVersion(connect *sql.DB, db, table string) (string, error) {
	sql := fmt.Sprintf("SELECT comment FROM system.columns WHERE database='%s' AND table='%s' AND name='time'",
		db, table)
	rows, err := connect.Query(sql)
	if err != nil {
		return "", err
	}
	var version string
	for rows.Next() {
		err := rows.Scan(&version)
		if err != nil {
			return "", err
		}
	}
	return version, nil
}

func (i *Issu) setTableVersion(connect *sql.DB, db, table string) error {
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` COMMENT COLUMN time '%s'",
		db, table, common.CK_VERSION)
	_, err := connect.Exec(sql)
	if err != nil {
		if strings.Contains(err.Error(), "doesn't exist") {
			log.Infof("db: %s, table: %s info: %s", db, table, err)
			return nil
		}
	}
	return err
}

func getColumnRenames(columnRenamess []*ColumnRenames) []*ColumnRename {
	renames := []*ColumnRename{}
	for _, columnRenames := range columnRenamess {
		for _, table := range columnRenames.Tables {
			for i, name := range columnRenames.OldColumnNames {
				renames = append(renames, &ColumnRename{
					Db:              columnRenames.Db,
					Table:           table,
					OldColumnName:   name,
					CheckColumnType: columnRenames.CheckColumnType,
					OldColumnType:   columnRenames.OldColumnType,
					NewColumnName:   columnRenames.NewColumnNames[i],
					DropIndex:       columnRenames.DropIndex,
					DropMvTable:     columnRenames.DropMvTable,
				})
			}
		}
	}
	return renames
}

func (i *Issu) renameColumns(connect *sql.DB) ([]*ColumnRename, error) {
	dones := []*ColumnRename{}
	for _, renameColumn := range i.columnRenames {
		version, err := i.getTableVersion(connect, renameColumn.Db, renameColumn.Table)
		if err != nil {
			if strings.Contains(err.Error(), "doesn't exist") {
				log.Infof("db: %s, table: %s info: %s", renameColumn.Db, renameColumn.Table, err)
				continue
			}
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}

		if err := i.renameColumn(connect, renameColumn); err != nil {
			return dones, err
		}
		dones = append(dones, renameColumn)
	}

	return dones, nil
}

func (i *Issu) modColumns(connect *sql.DB) ([]*ColumnMod, error) {
	dones := []*ColumnMod{}
	for _, modColumn := range i.columnMods {
		version, err := i.getTableVersion(connect, modColumn.Db, modColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.modColumn(connect, modColumn); err != nil {
			return dones, err
		}
		dones = append(dones, modColumn)
	}

	return dones, nil
}

func (i *Issu) dropColumns(connect *sql.DB) ([]*ColumnDrop, error) {
	dones := []*ColumnDrop{}
	for _, dropColumn := range i.columnDrops {
		version, err := i.getTableVersion(connect, dropColumn.Db, dropColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.dropColumn(connect, dropColumn); err != nil {
			return dones, err
		}
		dones = append(dones, dropColumn)
	}
	return dones, nil
}

func (i *Issu) modTableTTLs(connect *sql.DB) error {
	for _, modTTL := range i.modTTLs {
		version, err := i.getTableVersion(connect, modTTL.Db, modTTL.Table)
		if err != nil {
			log.Error(err)
			continue
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.modTTL(connect, modTTL); err != nil {
			log.Error(err)
			return err
		} else {
			if err := i.setTableVersion(connect, modTTL.Db, modTTL.Table); err != nil {
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

func (i *Issu) modTTL(connect *sql.DB, mt *TableModTTL) error {
	// ALTER TABLE vtap_acl."1m_local"  MODIFY TTL time + toIntervalHour(168);
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY TTL time + toIntervalHour(%d)",
		mt.Db, mt.Table, mt.NewTTL)
	log.Info("modify TTL: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		return err
	}
	return nil
}

func getColumnAdds(columnAdds *ColumnAdds) []*ColumnAdd {
	adds := []*ColumnAdd{}
	for _, db := range columnAdds.Dbs {
		for _, tbl := range columnAdds.Tables {
			for _, clmn := range columnAdds.ColumnNames {
				adds = append(adds, &ColumnAdd{
					Db:           db,
					Table:        tbl,
					ColumnName:   clmn,
					ColumnType:   columnAdds.ColumnType,
					DefaultValue: columnAdds.DefaultValue,
				})
			}
		}
	}
	return adds
}

func getIndexAdds(indexAddss []*IndexAdds) []*IndexAdd {
	adds := []*IndexAdd{}
	for _, indexAdds := range indexAddss {
		for _, db := range indexAdds.Dbs {
			for _, tbl := range indexAdds.Tables {
				for _, clmn := range indexAdds.ColumnNames {
					adds = append(adds, &IndexAdd{
						Db:         db,
						Table:      tbl,
						ColumnName: clmn,
						IndexType:  indexAdds.IndexType,
					})
				}
			}
		}
	}
	return adds
}

func (i *Issu) addColumns(connect *sql.DB) ([]*ColumnAdd, error) {
	dones := []*ColumnAdd{}
	for _, add := range i.columnAdds {
		version, err := i.getTableVersion(connect, add.Db, add.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			log.Infof("db(%s) table(%s) already updated", add.Db, add.Table)
			continue
		}
		if err := i.addColumn(connect, add); err != nil {
			return dones, err
		}
		dones = append(dones, add)
	}

	for _, tableName := range []string{
		zerodoc.VTAP_FLOW_PORT_1M.TableName(), zerodoc.VTAP_FLOW_EDGE_PORT_1M.TableName(),
		zerodoc.VTAP_APP_PORT_1M.TableName(), zerodoc.VTAP_APP_EDGE_PORT_1M.TableName()} {
		datasourceInfos, err := i.getUserDefinedDatasourceInfos(connect, ckdb.METRICS_DB, strings.Split(tableName, ".")[0])
		if err != nil {
			log.Warning(err)
			continue
		}
		for _, dsInfo := range datasourceInfos {
			adds, err := i.addColumnDatasource(connect, dsInfo, strings.Contains(tableName, "_edge_"), strings.Contains(tableName, "vtap_app"))
			if err != nil {
				return nil, nil
			}
			dones = append(dones, adds...)
		}
	}

	return dones, nil
}

func (i *Issu) addIndexs(connect *sql.DB) ([]*IndexAdd, error) {
	dones := []*IndexAdd{}
	for _, add := range i.indexAdds {
		version, err := i.getTableVersion(connect, add.Db, add.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			log.Infof("db(%s) table(%s) already updated", add.Db, add.Table)
			continue
		}
		if err := i.addIndex(connect, add); err != nil {
			log.Warningf("db(%s) table(%s) add index failed.err: %s", add.Db, add.Table, err)
			continue
		}
		dones = append(dones, add)
	}
	return dones, nil
}

func (i *Issu) Start() error {
	connects := i.Connections
	if len(connects) == 0 {
		return fmt.Errorf("connections is nil")
	}
	for _, connect := range connects {
		renames, errRenames := i.renameColumns(connect)
		if errRenames != nil {
			return errRenames
		}
		mods, errMods := i.modColumns(connect)
		if errMods != nil {
			return errMods
		}

		adds, errAdds := i.addColumns(connect)
		if errAdds != nil {
			return errAdds
		}

		addIndexs, errAddIndexs := i.addIndexs(connect)
		if errAddIndexs != nil {
			log.Warning(errAddIndexs)
		}

		drops, errDrops := i.dropColumns(connect)
		if errDrops != nil {
			return errDrops
		}

		for _, cr := range renames {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range mods {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range adds {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range addIndexs {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range drops {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		go i.modTableTTLs(connect)
	}
	return nil
}

func (i *Issu) Close() error {
	if len(i.Connections) == 0 {
		return nil
	}
	return i.Connections.Close()
}

func (i *Issu) renameUserDefineDatasource(connect *sql.DB, ds *datasource.DatasourceManager) error {
	for _, dbGroup := range []string{"vtap_flow", "vtap_app"} {
		dbName := dbGroup + "_port"
		datasourceInfos, err := i.getUserDefinedDatasourceInfos(connect, dbName, "")
		if err != nil {
			return err
		}
		for _, dsInfo := range datasourceInfos {
			if err := i.renameTable(connect, &TableRename{
				OldDb:     dsInfo.db,
				OldTables: []string{dsInfo.name + "_agg"},
				NewDb:     ckdb.METRICS_DB,
				NewTables: []string{fmt.Sprintf("%s.%s", dsInfo.db, dsInfo.name+"_agg")},
			}); err != nil {
				return err
			}
			interval := 60
			if dsInfo.interval == ckdb.TimeFuncDay {
				interval = 1440
			}
			if err := ds.Handle(dbGroup, "add", dsInfo.baseTable, dsInfo.name, dsInfo.summable, dsInfo.unsummable, interval, 7*24); err != nil {
				return err
			}
		}
	}

	return nil
}
