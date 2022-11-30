/*
 * Copyright (c) 2022 Yunshan Networks
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

	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/datasource"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("issu")

type Issu struct {
	cfg                *config.Config
	tableRenames       []*TableRename
	columnRenames      []*ColumnRename
	columnMods         []*ColumnMod
	columnAdds         []*ColumnAdd
	primaryConnection  *sql.DB
	primaryAddr        string
	username, password string
	exit               bool
}

type TableRename struct {
	OldDb     string
	OldTables []string
	NewDb     string
	NewTables []string
}

type ColumnRename struct {
	Db            string
	Table         string
	OldColumnName string
	NewColumnName string
	DropIndex     bool
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
		ColumnNames: []string{"resource_gl0_id_0", "resource_gl1_id_0", "resource_gl2_id_0", "resource_gl0_id_1", "resource_gl1_id_1", "resource_gl2_id_1"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"resource_gl0_type_0", "resource_gl1_type_0", "resource_gl2_type_0", "resource_gl0_type_1", "resource_gl1_type_1", "resource_gl2_type_1", "status"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_port", "vtap_app_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"resource_gl0_id", "resource_gl1_id", "resource_gl2_id"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_port", "vtap_app_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"resource_gl0_type", "resource_gl1_type", "resource_gl2_type"},
		ColumnType:  ckdb.UInt8,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_edge_port", "vtap_app_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"resource_gl0_id_0", "resource_gl1_id_0", "resource_gl2_id_0", "resource_gl0_id_1", "resource_gl1_id_1", "resource_gl2_id_1"},
		ColumnType:  ckdb.UInt32,
	},
	&ColumnAdds{
		Dbs:         []string{"vtap_flow_edge_port", "vtap_app_edge_port"},
		Tables:      []string{"1m", "1m_local", "1s", "1s_local"},
		ColumnNames: []string{"resource_gl0_type_0", "resource_gl1_type_0", "resource_gl2_type_0", "resource_gl0_type_1", "resource_gl1_type_1", "resource_gl2_type_1"},
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

type DatasourceInfo struct {
	db         string
	name       string
	baseTable  string
	summable   string
	unsummable string
	interval   ckdb.TimeFuncType
}

func getDatasourceInfo(connect *sql.DB, db, name string) (*DatasourceInfo, error) {
	sql := fmt.Sprintf("SHOW CREATE TABLE %s.`%s_mv`", db, name)
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
	if strings.HasPrefix(name, "vtap_app") {
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
		name:       name,
		summable:   summable,
		unsummable: unsummable,
		interval:   intervalTime,
	}, nil
}

// 找出自定义数据源和参数
func getUserDefinedDatasourceInfos(connect *sql.DB, db, tableName string) ([]*DatasourceInfo, error) {
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
		ds, err := getDatasourceInfo(connect, db, name)
		if err != nil {
			return nil, err
		}
		dSInfos = append(dSInfos, ds)
	}

	return dSInfos, nil
}

func (i *Issu) addColumnDatasource(connect *sql.DB, d *DatasourceInfo) ([]*ColumnAdd, error) {
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

	for _, adds := range columnAddss612 {
		columnAdds = append(columnAdds, getColumnAdds(adds)...)
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
		cfg:         cfg,
		primaryAddr: cfg.CKDB.ActualAddr,
		username:    cfg.CKDBAuth.Username,
		password:    cfg.CKDBAuth.Password,
	}

	allVersionAdds := [][]*ColumnAdds{ColumnAdd612, ColumnAdd613, ColumnAdd615, ColumnAdd618}
	i.columnAdds = []*ColumnAdd{}
	for _, versionAdd := range allVersionAdds {
		for _, adds := range versionAdd {
			i.columnAdds = append(i.columnAdds, getColumnAdds(adds)...)
		}
	}

	i.columnMods = ColumnMod615
	i.columnRenames = ColumnRename618

	var err error
	i.primaryConnection, err = common.NewCKConnection(i.primaryAddr, i.username, i.password)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (i *Issu) RunRenameTable(ds *datasource.DatasourceManager) error {
	for _, tableRename := range i.tableRenames {
		if err := i.renameTable(i.primaryConnection, tableRename); err != nil {
			return err
		}
	}

	if err := i.renameUserDefineDatasource(i.primaryConnection, ds); err != nil {
		log.Warning(err)
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
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) renameColumn(connect *sql.DB, cr *ColumnRename) error {
	if cr.DropIndex {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx",
			cr.Db, cr.Table, cr.OldColumnName)
		log.Info("drop index: ", sql)
		_, err := connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "Cannot find index") {
				log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			} else {
				log.Error(err)
				return err
			}
		}
	}

	// ALTER TABLE flow_log.l4_flow_log  RENAME COLUMN retan_tx TO retran_tx
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` RENAME COLUMN %s to %s",
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
	return err
}

func (i *Issu) renameColumns(connect *sql.DB) ([]*ColumnRename, error) {
	dones := []*ColumnRename{}
	for _, renameColumn := range i.columnRenames {
		version, err := i.getTableVersion(connect, renameColumn.Db, renameColumn.Table)
		if err != nil {
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
		datasourceInfos, err := getUserDefinedDatasourceInfos(connect, ckdb.METRICS_DB, tableName)
		if err != nil {
			log.Warning(err)
			continue
		}
		for _, dsInfo := range datasourceInfos {
			adds, err := i.addColumnDatasource(connect, dsInfo)
			if err != nil {
				return nil, nil
			}
			dones = append(dones, adds...)
		}
	}

	return dones, nil
}

func (i *Issu) Start() error {
	connect := i.primaryConnection
	if connect == nil {
		return fmt.Errorf("primary connection is nil")
	}
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
	return nil
}

func (i *Issu) Close() error {
	if i.primaryConnection == nil {
		return nil
	}
	return i.primaryConnection.Close()
}

func (i *Issu) renameUserDefineDatasource(connect *sql.DB, ds *datasource.DatasourceManager) error {
	for _, dbGroup := range []string{"vtap_flow", "vtap_app"} {
		dbName := dbGroup + "_port"
		datasourceInfos, err := getUserDefinedDatasourceInfos(connect, dbName, "")
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
