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

package ckissu

import (
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

var AllColumnAdds = [][]*ColumnAdds{ColumnAdd64, ColumnAdd65}
var AllIndexAdds = [][]*IndexAdd{getIndexAdds(IndexAdd64), getIndexAdds(IndexAdd65)}
var AllColumnMods = [][]*ColumnMod{}
var AllColumnRenames = [][]*ColumnRename{getColumnRenames(ColumnRename65)}
var AllColumnDrops = [][]*ColumnDrop{getColumnDrops(nil)}
var AllTableModTTLs = [][]*TableModTTL{}
var AllTableRenames = []*TableRename{}
var AllDatasourceAdds = [][]*ColumnDatasourceAdd{getColumnDatasourceAdds(ColumnDatasourceAdd65)}

var ColumnAdd64 = []*ColumnAdds{
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"syscall_coroutine_0", "syscall_coroutine_1", "trace_id_index"},
		ColumnType:  ckdb.UInt64,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"is_tls"},
		ColumnType:  ckdb.UInt8,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"rtt_client", "rtt_server"},
		ColumnType:  ckdb.Float64,
	},
	{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process", "in_process_local"},
		ColumnNames: []string{"gprocess_id"},
		ColumnType:  ckdb.UInt32,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"tls_rtt"},
		ColumnType:  ckdb.Float64,
	},
}

var IndexAdd64 = []*IndexAdds{
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log_local"},
		ColumnNames: []string{"trace_id", "x_request_id_0", "x_request_id_1", "request_resource", "request_domain", "endpoint"},
		IndexType:   ckdb.IndexBloomfilter,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log_local"},
		ColumnNames: []string{"_id", "trace_id_index"},
		IndexType:   ckdb.IndexMinmax,
	},
}

var IndexAdd65 = []*IndexAdds{
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log_local"},
		ColumnNames: []string{"request_domain"},
		IndexType:   ckdb.IndexBloomfilter,
	},
}

var ColumnAdd65 = []*ColumnAdds{
	{
		Dbs:         []string{"flow_metrics"},
		Tables:      []string{"traffic_policy.1m", "traffic_policy.1m_local"},
		ColumnNames: []string{"tunnel_ip_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"event"},
		Tables:      []string{"perf_event", "perf_event_local", "event", "event_local"},
		ColumnNames: []string{"process_kname"},
		ColumnType:  ckdb.String,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local"},
		ColumnNames: []string{"request_domain"},
		ColumnType:  ckdb.String,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log", "l7_flow_log_local"},
		ColumnNames: []string{"events"},
		ColumnType:  ckdb.String,
	},
	{
		Dbs: []string{"flow_metrics"},
		Tables: []string{"application.1m", "application.1m_local", "application_map.1m", "application_map.1m_local",
			"application.1s", "application.1s_local", "application_map.1s", "application_map.1s_local"},
		ColumnNames: []string{"biz_type"},
		ColumnType:  ckdb.UInt8,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l7_flow_log_local", "l7_flow_log"},
		ColumnNames: []string{"biz_type"},
		ColumnType:  ckdb.UInt8,
	},
	{
		Dbs:         []string{"event"},
		Tables:      []string{"perf_event", "perf_event_local", "event", "event_local"},
		ColumnNames: []string{"_id"},
		ColumnType:  ckdb.UInt64,
	},

	{
		Dbs: []string{"flow_metrics"},
		Tables: []string{"application.1m", "application.1m_local", "application_map.1m", "application_map.1m_local",
			"application.1s", "application.1s_local", "application_map.1s", "application_map.1s_local", "traffic_policy.1m", "traffic_policy.1m_local"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"flow_log"},
		Tables:      []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log_local", "l7_flow_log", "l4_packet_local", "l4_packet", "l7_packet_local", "l7_packet"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"event"},
		Tables:      []string{"event_local", "event", "alarm_event_local", "alarm_event", "perf_event", "perf_event_local"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"ext_metrics"},
		Tables:      []string{"metrics_local", "metrics"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"profile"},
		Tables:      []string{"in_process_local", "in_process"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"prometheus"},
		Tables:      []string{"samples_local", "samples"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs:         []string{"deepflow_system"},
		Tables:      []string{"deepflow_system_local", "deepflow_system"},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
	{
		Dbs: []string{"flow_tag"},
		Tables: []string{
			"deepflow_system_custom_field_local", "deepflow_system_custom_field",
			"deepflow_system_custom_field_value_local", "deepflow_system_custom_field_value",
			"event_custom_field_local", "event_custom_field_local",
			"event_custom_field_value_local", "event_custom_field_value",
			"ext_metrics_custom_field_local", "ext_metrics_custom_field",
			"ext_metrics_custom_field_value_local", "ext_metrics_custom_field_value",
			"flow_log_custom_field_local", "flow_log_custom_field",
			"flow_log_custom_field_value_local", "flow_log_custom_field_value",
		},
		ColumnNames: []string{"team_id"},
		ColumnType:  ckdb.UInt16,
	},
}

var TableRenames65 = []*TableRename{
	{
		OldDb: "flow_metrics",
		OldTables: []string{
			"vtap_app_port.1m_local", "vtap_app_port.1s_local", "vtap_app_edge_port.1m_local", "vtap_app_edge_port.1s_local",
			"vtap_flow_port.1m_local", "vtap_flow_port.1s_local", "vtap_flow_edge_port.1m_local", "vtap_flow_edge_port.1s_local",
			"vtap_acl.1m_local"},
		NewDb: "flow_metrics",
		NewTables: []string{
			"application.1m_local", "application.1s_local", "application_map.1m_local", "application_map.1s_local",
			"network.1m_local", "network.1s_local", "network_map.1m_local", "network_map.1s_local",
			"traffic_policy.1m_local"},
	},
}

var ColumnRename65 = []*ColumnRenames{
	{
		Db:             "flow_log",
		Tables:         []string{"l4_packet", "l4_packet_local", "l7_packet", "l7_packet_local"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},
	{
		Db:             "ext_metrics",
		Tables:         []string{"metrics", "metrics_local"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},
	{
		Db:             "prometheus",
		Tables:         []string{"samples", "samples_local"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},
	{
		Db:             "event",
		Tables:         []string{"event", "event_local", "perf_event", "perf_event_local"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},
	{
		Db:             "profile",
		Tables:         []string{"in_process", "in_process_local"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},

	{
		Db:             "flow_log",
		Tables:         []string{"l4_flow_log", "l4_flow_log_local"},
		OldColumnNames: []string{"tap_type"},
		NewColumnNames: []string{"capture_network_type_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt8},
	},
	{
		Db:             "flow_log",
		Tables:         []string{"l7_flow_log", "l7_flow_log_local"},
		OldColumnNames: []string{"tap_type"},
		NewColumnNames: []string{"capture_network_type_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt8},
	},
	{
		Db: "flow_metrics",
		Tables: []string{
			"application.1m_local", "application.1s_local", "network.1m_local", "network.1s_local",
			"application.1m", "application.1s", "network.1m", "network.1s",
		},
		OldColumnNames: []string{"vtap_id", "tap_type"},
		NewColumnNames: []string{"agent_id", "capture_network_type_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16, ckdb.UInt8},
	},
	{
		Db:             "flow_metrics",
		Tables:         []string{"traffic_policy.1m_local", "traffic_policy.1m"},
		OldColumnNames: []string{"vtap_id"},
		NewColumnNames: []string{"agent_id"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16},
	},

	{
		Db:             "flow_log",
		Tables:         []string{"l4_flow_log", "l4_flow_log_local", "l7_flow_log", "l7_flow_log_local"},
		OldColumnNames: []string{"vtap_id", "tap_side", "tap_port", "tap_port_type"},
		NewColumnNames: []string{"agent_id", "observation_point", "capture_nic", "capture_nic_type"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16, ckdb.LowCardinalityString, ckdb.UInt32, ckdb.UInt8},
	},
	{
		Db: "flow_metrics",
		Tables: []string{
			"application_map.1m_local", "application_map.1s_local", "network_map.1m_local", "network_map.1s_local",
			"application_map.1m", "application_map.1s", "network_map.1m", "network_map.1s",
		},
		OldColumnNames: []string{"vtap_id", "tap_type", "tap_side", "tap_port", "tap_port_type"},
		NewColumnNames: []string{"agent_id", "capture_network_type_id", "observation_point", "capture_nic", "capture_nic_type"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt16, ckdb.UInt8, ckdb.LowCardinalityString, ckdb.UInt32, ckdb.UInt8},
	},
	{
		Db: "flow_metrics",
		Tables: []string{
			"network.1m_local", "network.1s_local", "network.1m", "network.1s",
			"network_map.1m_local", "network_map.1s_local", "network_map.1m", "network_map.1s",
		},
		OldColumnNames: []string{"client_syn_repeat", "server_syn_ack_repeat"},
		NewColumnNames: []string{"server_syn_miss", "client_ack_miss"},
		OldColumnTypes: []ckdb.ColumnType{ckdb.UInt64, ckdb.UInt64},
	},
}

var ColumnDatasourceAdd65 = []*ColumnDatasourceAdds{
	{
		ColumnNames:    []string{"agent_id", "capture_network_type_id"},
		OldColumnNames: []string{"vtap_id", "tap_type"},
		ColumnTypes:    []ckdb.ColumnType{ckdb.UInt16, ckdb.UInt8},
		OnlyMapTable:   false,
		OnlyAppTable:   false,
	},
	{
		ColumnNames:    []string{"observation_point", "capture_nic", "capture_nic_type"},
		OldColumnNames: []string{"tap_side", "tap_port", "tap_port_type"},
		ColumnTypes:    []ckdb.ColumnType{ckdb.LowCardinalityString, ckdb.UInt32, ckdb.UInt8},
		OnlyMapTable:   true,
		OnlyAppTable:   false,
	},
	{
		ColumnNames:    []string{"biz_type"},
		OldColumnNames: []string{""},
		ColumnTypes:    []ckdb.ColumnType{ckdb.UInt8},
		OnlyMapTable:   false,
		OnlyAppTable:   true,
	},
}
