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

package datasource

import (
	"fmt"
	"reflect"
	"strings"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	ORIGIN_TABLE_1M = "1m"
	ORIGIN_TABLE_1S = "1s"
	NETWORK         = "network"
	APPLICATION     = "application"
	TRAFFIC_POLICY  = "traffic_policy"
	FLOW_TAG_DB     = "flow_tag"

	ERR_IS_MODIFYING = "Modifying the retention time (%s), please try again later"
)

type DatasourceModifiedOnly string
type DatasourceInfo struct {
	ID            int
	DB            string
	Tables        []string
	FlowTagTables []string
}

const (
	DEEPFLOW_SYSTEM   DatasourceModifiedOnly = "deepflow_system"
	L4_FLOW_LOG                              = "flow_log.l4_flow_log"
	L7_FLOW_LOG                              = "flow_log.l7_flow_log"
	L4_PACKET                                = "flow_log.l4_packet"
	L7_PACKET                                = "flow_log.l7_packet"
	EXT_METRICS                              = "ext_metrics"
	PROMETHEUS                               = "prometheus"
	EVENT_EVENT                              = "event.event"
	EVENT_PERF_EVENT                         = "event.perf_event"
	EVENT_ALERT_EVENT                        = "event.alert_event"
	PROFILE                                  = "profile.in_process"
	APPLOG                                   = "application_log.log"
	DEEPFLOW_TENANT                          = "deepflow_tenant"
	DEEPFLOW_ADMIN                           = "deepflow_admin"
)

// to modify the datasource TTL, you need to also modify the 'flow_tag' database tables.
// FIXME: only the 'prometheus' database is supported now, and the remaining databases will be completed in the future.
var DatasourceModifiedOnlyIDMap = map[DatasourceModifiedOnly]DatasourceInfo{
	DEEPFLOW_SYSTEM:   {int(flow_metrics.METRICS_TABLE_ID_MAX) + 1, "deepflow_system", []string{"deepflow_system"}, []string{}},
	L4_FLOW_LOG:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 2, "flow_log", []string{"l4_flow_log"}, []string{}},
	L7_FLOW_LOG:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 3, "flow_log", []string{"l7_flow_log"}, []string{}},
	L4_PACKET:         {int(flow_metrics.METRICS_TABLE_ID_MAX) + 4, "flow_log", []string{"l4_packet"}, []string{}},
	L7_PACKET:         {int(flow_metrics.METRICS_TABLE_ID_MAX) + 5, "flow_log", []string{"l7_packet"}, []string{}},
	EXT_METRICS:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 6, "ext_metrics", []string{"metrics"}, []string{}},
	PROMETHEUS:        {int(flow_metrics.METRICS_TABLE_ID_MAX) + 7, "prometheus", []string{"samples"}, []string{"prometheus_custom_field", "prometheus_custom_field_value"}},
	EVENT_EVENT:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 8, "event", []string{"event"}, []string{}},
	EVENT_PERF_EVENT:  {int(flow_metrics.METRICS_TABLE_ID_MAX) + 9, "event", []string{"perf_event"}, []string{}},
	EVENT_ALERT_EVENT: {int(flow_metrics.METRICS_TABLE_ID_MAX) + 10, "event", []string{"alert_event"}, []string{}},
	PROFILE:           {int(flow_metrics.METRICS_TABLE_ID_MAX) + 11, "profile", []string{"in_process", "in_process.1s_agg"}, []string{}},
	APPLOG:            {int(flow_metrics.METRICS_TABLE_ID_MAX) + 12, "application_log", []string{"log"}, []string{}},
	DEEPFLOW_TENANT:   {int(flow_metrics.METRICS_TABLE_ID_MAX) + 13, "deepflow_tenant", []string{"deepflow_collector"}, []string{}},
	DEEPFLOW_ADMIN:    {int(flow_metrics.METRICS_TABLE_ID_MAX) + 14, "deepflow_admin", []string{"deepflow_server"}, []string{}},
}

func (ds DatasourceModifiedOnly) DatasourceInfo() DatasourceInfo {
	return DatasourceModifiedOnlyIDMap[ds]
}

func IsModifiedOnlyDatasource(datasource string) bool {
	_, ok := DatasourceModifiedOnlyIDMap[DatasourceModifiedOnly(datasource)]
	return ok
}

var metricsGroupTableIDs = [][]flow_metrics.MetricsTableID{
	flow_metrics.NETWORK_1M:        {flow_metrics.NETWORK_MAP_1M, flow_metrics.NETWORK_1M},
	flow_metrics.NETWORK_1S:        {flow_metrics.NETWORK_MAP_1S, flow_metrics.NETWORK_1S},
	flow_metrics.APPLICATION_1M:    {flow_metrics.APPLICATION_MAP_1M, flow_metrics.APPLICATION_1M},
	flow_metrics.APPLICATION_1S:    {flow_metrics.APPLICATION_MAP_1S, flow_metrics.APPLICATION_1S},
	flow_metrics.TRAFFIC_POLICY_1M: {flow_metrics.TRAFFIC_POLICY_1M},
}

func getMetricsSubTableIDs(tableGroup, baseTable string) ([]flow_metrics.MetricsTableID, error) {
	switch tableGroup {
	case NETWORK:
		if baseTable == ORIGIN_TABLE_1S {
			return metricsGroupTableIDs[flow_metrics.NETWORK_1S], nil
		} else {
			return metricsGroupTableIDs[flow_metrics.NETWORK_1M], nil
		}
	case APPLICATION:
		if baseTable == ORIGIN_TABLE_1S {
			return metricsGroupTableIDs[flow_metrics.APPLICATION_1S], nil
		} else {
			return metricsGroupTableIDs[flow_metrics.APPLICATION_1M], nil
		}
	case TRAFFIC_POLICY:
		return metricsGroupTableIDs[flow_metrics.TRAFFIC_POLICY_1M], nil
	default:
		return nil, fmt.Errorf("unknown table group(%s)", tableGroup)
	}
}

// flow_metrics 的 Latency 结构中的非累加聚合字段
var unsummableMaxFieldsMap = map[string]struct{}{
	"rtt_max":        {},
	"rtt_client_max": {},
	"rtt_server_max": {},
	"srt_max":        {},
	"art_max":        {},
	"rrt_max":        {},
	"cit_max":        {},

	"direction_score": {},
}

// 对于unsumable的sum列使用max,min聚合时, count列取相应的max,min列的值
var unsummableFieldsMap = map[string]struct{}{
	"rtt_sum":        {},
	"rtt_client_sum": {},
	"rtt_server_sum": {},
	"srt_sum":        {},
	"art_sum":        {},
	"rrt_sum":        {},
	"cit_sum":        {},

	"rtt_count":        {},
	"rtt_client_count": {},
	"rtt_server_count": {},
	"srt_count":        {},
	"art_count":        {},
	"rrt_count":        {},
	"cit_count":        {},
}

func getColumnString(column *ckdb.Column, aggrSummable, aggrUnsummable string, t TableType) string {
	_, isUnsummable := unsummableFieldsMap[column.Name]
	isMaxMinAggr := (aggrUnsummable == aggrStrings[MAX]) || (aggrUnsummable == aggrStrings[MIN])
	_, isUnsummableMax := unsummableMaxFieldsMap[column.Name]

	// 'max', 'min' aggregation of 'xxx_count', 'xxx_sum' fields, use 'argMax', 'argMin' aggregation
	if isUnsummable && isMaxMinAggr {
		aggrFunc := "argMax"
		if aggrUnsummable == aggrStrings[MIN] {
			aggrFunc = "argMin"
		}
		switch t {
		case AGG:
			// 例如: rtt_count__agg AggregateFunction(argMax, UInt64, Float64),
			//   argMax的参数类型是UInt64和Float64， 当第二个参数的值最大时，rtt_count__agg 值为第一个参数的值
			return fmt.Sprintf("%s__%s AggregateFunction(%s, %s, Float64)", column.Name, AGG.String(), aggrFunc, column.Type.String()) // sum列默认是float64
		case MV:
			// 例如: argMaxState(rtt_count, rtt_sum/(rtt_count+0.01)) AS rtt_count__agg, 防止除0异常，除数加0.01
			//   表示 当 rtt_sum/(rtt_count+0.01) 为最大值时，rtt_count__agg 的值为 rtt_count的值
			return fmt.Sprintf("%sState(%s, %s/(%s+0.01)) AS %s__%s", aggrFunc, column.Name,
				strings.ReplaceAll(column.Name, "count", "sum"), strings.ReplaceAll(column.Name, "sum", "count"), // 总是取 xxx_sum/xxx_count 的值
				column.Name, AGG.String())
		case LOCAL:
			// 例如： finalizeAggregation(rtt_count__agg) as rtt_count,
			return fmt.Sprintf("finalizeAggregation(%s__%s) AS %s", column.Name, AGG.String(), column.Name)
		}
	} else {
		var aggr string
		if isUnsummable {
			// 'avg' aggregation of 'xxx_count', 'xxx_sum' fields, using 'sum' aggregation
			aggr = aggrStrings[SUM]
		} else if isUnsummableMax {
			// 'max', 'min', 'avg' aggregation of 'xxx_max' fields, use 'max', 'min', 'avg' aggregation
			aggr = aggrUnsummable
		} else {
			// summable aggregation
			aggr = aggrSummable
		}

		switch t {
		case AGG:
			return fmt.Sprintf("%s__%s AggregateFunction(%s, %s)", column.Name, t.String(), aggr, column.Type.String())
		case MV:
			return fmt.Sprintf("%sState(%s) AS %s__%s", aggr, column.Name, column.Name, AGG.String())
		case LOCAL:
			return fmt.Sprintf("finalizeAggregation(%s__%s) AS %s", column.Name, AGG.String(), column.Name)
		}
	}

	return ""
}

type ActionEnum uint8

const (
	ADD ActionEnum = iota
	DEL
	MOD
)

var actionStrings = []string{
	ADD: "add",
	DEL: "del",
	MOD: "mod",
}

func ActionToEnum(action string) (ActionEnum, error) {
	for i, a := range actionStrings {
		if action == a {
			return ActionEnum(i), nil
		}
	}
	return 0, fmt.Errorf("unknown action %s", action)
}

type AggrEnum uint8

const (
	SUM AggrEnum = iota
	MAX
	MIN
	AVG
)

var aggrStrings = []string{
	SUM: "sum",
	MAX: "max",
	MIN: "min",
	AVG: "avg",
}

func AggrToEnum(aggr string) (AggrEnum, error) {
	for i, a := range aggrStrings {
		if aggr == a {
			return AggrEnum(i), nil
		}
	}
	return 0, fmt.Errorf("unknown aggr %s", aggr)
}

type TableType uint8

const (
	AGG    TableType = iota // 聚合后的原始表, 存储数据
	MV                      // view 无实际数据, 用来从local或agg表，读取数据写入到agg表
	LOCAL                   // view 无实际数据, 用来简化读取agg表的数据
	GLOBAL                  // 以local表为基础，建立全局表
)

var tableTypeStrings = []string{
	AGG:    "agg",
	MV:     "mv",
	LOCAL:  "local",
	GLOBAL: "",
}

func (v TableType) String() string {
	return tableTypeStrings[v]
}

type IntervalEnum uint8

const (
	IntervalHour IntervalEnum = iota
	IntervalDay
)

func getMetricsTableName(id uint8, db, table string, t TableType) string {
	tableId := flow_metrics.MetricsTableID(id)
	tablePrefix := strings.Split(tableId.TableName(), ".")[0]
	if len(table) == 0 {
		if t == GLOBAL {
			return fmt.Sprintf("%s.`%s`", db, tableId.TableName())
		}
		return fmt.Sprintf("%s.`%s_%s`", db, tableId.TableName(), t.String())
	}
	if t == GLOBAL {
		return fmt.Sprintf("%s.`%s.%s`", db, tablePrefix, table)
	}
	return fmt.Sprintf("%s.`%s.%s_%s`", db, tablePrefix, table, t.String())
}

func stringSliceHas(items []string, item string) bool {
	for _, s := range items {
		if s == item {
			return true
		}
	}
	return false
}

func (m *DatasourceManager) makeTTLString(timeKey, db, table string, duration int) string {
	coldStorage := ckdb.GetColdStorage(m.ckdbColdStorages, db, table)
	if coldStorage.Enabled {
		return fmt.Sprintf("%s + toIntervalHour(%d), %s +  toIntervalHour(%d) TO %s '%s'",
			timeKey, duration,
			timeKey, coldStorage.TTLToMove, coldStorage.Type, coldStorage.Name)
	}
	return fmt.Sprintf("%s + toIntervalHour(%d)", timeKey, duration)
}

func (m *DatasourceManager) makeAggTableCreateSQL(t *ckdb.Table, db, dstTable, aggrSummable, aggrUnsummable string, partitionTime ckdb.TimeFuncType, duration int) string {
	aggTable := getMetricsTableName(t.ID, db, dstTable, AGG)

	columns := []string{}
	orderKeys := t.OrderKeys
	for _, p := range t.Columns {
		// 跳过_开头的字段，如_tid, _id
		if strings.HasPrefix(p.Name, "_") {
			continue
		}
		codec := ""
		if p.Codec != ckdb.CodecDefault {
			codec = fmt.Sprintf("codec(%s)", p.Codec.String())
		}

		if p.Name == t.TimeKey {
			p.Comment = t.Version
		}

		if p.GroupBy {
			if !stringSliceHas(orderKeys, p.Name) {
				orderKeys = append(orderKeys, p.Name)
			}
			comment := ""
			if p.Comment != "" {
				comment = fmt.Sprintf("COMMENT '%s'", p.Comment)
			}
			columns = append(columns, fmt.Sprintf("%s %s %s %s", p.Name, p.Type.String(), comment, codec))
		} else {
			columns = append(columns, getColumnString(p, aggrSummable, aggrUnsummable, AGG))
		}
	}

	engine := ckdb.AggregatingMergeTree.String()
	if t.DBType == ckdb.CKDBTypeByconity {
		engine = ckdb.CnchAggregatingMergeTree.String()
	}
	if m.replicaEnabled {
		engine = fmt.Sprintf(ckdb.ReplicatedAggregatingMergeTree.String(), db, dstTable+"_"+AGG.String())
	}

	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s
				   (%s)
				   ENGINE=%s
				   PRIMARY KEY (%s)
				   ORDER BY (%s)
				   PARTITION BY %s
				   TTL %s
				   SETTINGS storage_policy = '%s'`,
		aggTable,
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(orderKeys, ","), // 以order by的字段排序, 相同的做聚合
		partitionTime.String(t.TimeKey),
		m.makeTTLString(t.TimeKey, ckdb.METRICS_DB, t.GlobalName, duration),
		t.StoragePolicy)
}

func MakeMVTableCreateSQL(t *ckdb.Table, db, dstTable, aggrSummable, aggrUnsummable string, aggrTimeFunc ckdb.TimeFuncType) string {
	tableMv := getMetricsTableName(t.ID, db, dstTable, MV)
	tableAgg := getMetricsTableName(t.ID, db, dstTable, AGG)

	// 对于从1m,1s表进行聚合的表，使用local表作为源表
	baseTableType := LOCAL
	if t.DBType == ckdb.CKDBTypeByconity {
		baseTableType = GLOBAL
	}
	columnTableType := MV
	tableBase := getMetricsTableName(t.ID, db, "", baseTableType)

	groupKeys := t.OrderKeys
	columns := []string{}
	for _, p := range t.Columns {
		if strings.HasPrefix(p.Name, "_") {
			continue
		}
		if p.GroupBy {
			if p.Name == t.TimeKey {
				columns = append(columns, fmt.Sprintf("%s AS %s", aggrTimeFunc.String(t.TimeKey), t.TimeKey))
			} else {
				columns = append(columns, p.Name)
			}
			if !stringSliceHas(groupKeys, p.Name) {
				groupKeys = append(groupKeys, p.Name)
			}
		} else {
			columns = append(columns, getColumnString(p, aggrSummable, aggrUnsummable, columnTableType))
		}
	}

	return fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s
			AS SELECT %s
	                FROM %s
			GROUP BY %s`,
		tableMv, tableAgg,
		strings.Join(columns, ",\n"),
		tableBase,
		strings.Join(groupKeys, ","))
}

func MakeCreateTableLocal(t *ckdb.Table, db, dstTable, aggrSummable, aggrUnsummable string) string {
	tableAgg := getMetricsTableName(t.ID, db, dstTable, AGG)
	tableLocal := getMetricsTableName(t.ID, db, dstTable, LOCAL)
	if t.DBType == ckdb.CKDBTypeByconity {
		tableLocal = getMetricsTableName(t.ID, db, dstTable, GLOBAL)
	}

	columns := []string{}
	groupKeys := t.OrderKeys
	for _, p := range t.Columns {
		if strings.HasPrefix(p.Name, "_") {
			continue
		}
		if p.GroupBy {
			columns = append(columns, p.Name)
			if !stringSliceHas(groupKeys, p.Name) {
				groupKeys = append(groupKeys, p.Name)
			}
		} else {
			columns = append(columns, getColumnString(p, aggrSummable, aggrUnsummable, LOCAL))
		}
	}

	return fmt.Sprintf(`
CREATE VIEW IF NOT EXISTS %s
AS SELECT
%s
FROM %s`,
		tableLocal,
		strings.Join(columns, ",\n"),
		tableAgg)
}

func MakeGlobalTableCreateSQL(t *ckdb.Table, db, dstTable string) string {
	if t.DBType == ckdb.CKDBTypeByconity {
		return "SELECT VERSION()"
	}
	tableGlobal := getMetricsTableName(t.ID, db, dstTable, GLOBAL)
	tableLocal := getMetricsTableName(t.ID, db, dstTable, LOCAL)
	tablePrefix := strings.Split(t.GlobalName, ".")[0]
	engine := fmt.Sprintf(ckdb.Distributed.String(), t.Cluster, db, tablePrefix+"."+dstTable+"_"+LOCAL.String())

	createTable := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s AS %s ENGINE = %s",
		tableGlobal, tableLocal, engine)
	return createTable
}

func (m *DatasourceManager) getMetricsTable(id flow_metrics.MetricsTableID) *ckdb.Table {
	return flow_metrics.GetMetricsTables(ckdb.MergeTree, basecommon.CK_VERSION, m.ckdbCluster, m.ckdbStoragePolicy, m.ckdbType, 7, 1, 7, 1, m.ckdbColdStorages)[id]
}

func (m *DatasourceManager) createTableMV(cks basecommon.DBs, db string, tableId flow_metrics.MetricsTableID, baseTable, dstTable, aggrSummable, aggrUnsummable string, aggInterval IntervalEnum, duration int) error {
	table := m.getMetricsTable(tableId)
	if baseTable != ORIGIN_TABLE_1M && baseTable != ORIGIN_TABLE_1S {
		return fmt.Errorf("Only support base data_source 1s,1m")
	}

	aggTime := ckdb.TimeFuncHour
	partitionTime := ckdb.TimeFuncWeek
	if aggInterval == IntervalDay {
		aggTime = ckdb.TimeFuncDay
		partitionTime = ckdb.TimeFuncYYYYMM
	}

	commands := []string{
		m.makeAggTableCreateSQL(table, db, dstTable, aggrSummable, aggrUnsummable, partitionTime, duration),
		MakeMVTableCreateSQL(table, db, dstTable, aggrSummable, aggrUnsummable, aggTime),
		MakeCreateTableLocal(table, db, dstTable, aggrSummable, aggrUnsummable),
		MakeGlobalTableCreateSQL(table, db, dstTable),
	}
	for _, cmd := range commands {
		log.Info(cmd)
		if _, err := cks.Exec(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (m *DatasourceManager) modTableMV(cks basecommon.DBs, tableId flow_metrics.MetricsTableID, db, dstTable string, duration int) error {
	table := m.getMetricsTable(tableId)
	tableMod := ""
	if dstTable == ORIGIN_TABLE_1M || dstTable == ORIGIN_TABLE_1S {
		tableMod = getMetricsTableName(uint8(tableId), db, "", LOCAL)
		if m.ckdbType == ckdb.CKDBTypeByconity {
			tableMod = getMetricsTableName(uint8(tableId), db, "", GLOBAL)
		}
	} else {
		tableMod = getMetricsTableName(uint8(tableId), db, dstTable, AGG)
	}
	modTable := fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s",
		tableMod, m.makeTTLString(table.TimeKey, db, table.GlobalName, duration))

	_, err := cks.ExecParallel(modTable)
	return err
}

func delTableMV(cks basecommon.DBs, dbId flow_metrics.MetricsTableID, db, table string) error {
	dropTables := []string{
		getMetricsTableName(uint8(dbId), db, table, GLOBAL),
		getMetricsTableName(uint8(dbId), db, table, LOCAL),
		getMetricsTableName(uint8(dbId), db, table, MV),
		getMetricsTableName(uint8(dbId), db, table, AGG),
	}
	for _, name := range dropTables {
		if _, err := cks.Exec("DROP TABLE IF EXISTS " + name); err != nil {
			return err
		}
	}

	return nil
}

func isAggTable(table string) bool {
	return strings.HasSuffix(table, "_agg")
}

func (m *DatasourceManager) modTableTTL(cks basecommon.DBs, db, table string, duration int) error {
	ttlTable := fmt.Sprintf("%s.`%s_%s`", db, table, LOCAL)
	if m.ckdbType == ckdb.CKDBTypeByconity || isAggTable(table) {
		ttlTable = fmt.Sprintf("%s.`%s`", db, table)
	}
	modTable := fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s",
		ttlTable, m.makeTTLString("time", db, table, duration))
	_, err := cks.ExecParallel(modTable)
	return err
}

func (m *DatasourceManager) updateCKConnections() {
	if len(m.cks) == 0 || !reflect.DeepEqual(m.currentCkAddrs, *m.ckAddrs) {
		log.Infof("data_source clickhouse endpoints change from %+v to %+v", m.currentCkAddrs, *m.ckAddrs)
		m.currentCkAddrs = utils.CloneStringSlice(*m.ckAddrs)
		m.cks.Close()
		cks, err := basecommon.NewCKConnections(m.currentCkAddrs, m.user, m.password)
		if err != nil {
			log.Errorf("create clickhouse connections failed: %s", err)
		}
		m.cks = cks
	}
}

func (m *DatasourceManager) Handle(orgID int, action ActionEnum, dbGroup, baseTable, dstTable, aggrSummable, aggrUnsummable string, interval, duration int) error {
	m.updateCKConnections()
	if len(m.cks) == 0 {
		return fmt.Errorf("clickhouse connections is empty")
	}
	if IsModifiedOnlyDatasource(dbGroup) && action == MOD {
		datasoureInfo := DatasourceModifiedOnly(dbGroup).DatasourceInfo()
		datasourceId := datasoureInfo.ID
		db := ckdb.OrgDatabasePrefix(uint16(orgID)) + datasoureInfo.DB
		tables := datasoureInfo.Tables
		flowTagDb := ckdb.OrgDatabasePrefix(uint16(orgID)) + FLOW_TAG_DB
		flowTagTables := datasoureInfo.FlowTagTables

		if m.isModifyingFlags[orgID][datasourceId] {
			return fmt.Errorf(ERR_IS_MODIFYING, dbGroup)
		}
		go func(tableNames, flowTagTableNames []string, id int) {
			m.isModifyingFlags[orgID][id] = true
			for _, tableName := range tableNames {
				if err := m.modTableTTL(m.cks, db, tableName, duration); err != nil {
					log.Info(err)
				}
			}
			for _, tableName := range flowTagTableNames {
				if err := m.modTableTTL(m.cks, flowTagDb, tableName, duration); err != nil {
					log.Info(err)
				}
			}
			m.isModifyingFlags[orgID][id] = false
		}(tables, flowTagTables, datasourceId)

		return nil
	}

	table := baseTable
	if table == "" {
		table = dstTable
	}
	subTableIDs, err := getMetricsSubTableIDs(dbGroup, table)
	if err != nil {
		return err
	}

	if action == ADD {
		if baseTable == "" {
			return fmt.Errorf("base table name is empty")
		}
		if _, err := AggrToEnum(aggrSummable); err != nil {
			return err
		}
		if _, err := AggrToEnum(aggrUnsummable); err != nil {
			return err
		}
		if interval != 60 && interval != 1440 {
			return fmt.Errorf("interval(%d) only support 60 or 1440.", interval)
		}
		if duration < 1 {
			return fmt.Errorf("duration(%d) must bigger than 0.", duration)
		}
		if baseTable == dstTable {
			return fmt.Errorf("base table(%s) should not the same as the dst table(%s)", baseTable, dstTable)
		}
	}

	if dstTable == "" {
		return fmt.Errorf("dst table name is empty")
	}

	db := ckdb.OrgDatabasePrefix(uint16(orgID)) + ckdb.METRICS_DB
	for _, tableId := range subTableIDs {
		switch action {
		case ADD:
			aggInterval := IntervalHour
			if interval == 1440 {
				aggInterval = IntervalDay
			}
			if err := m.createTableMV(m.cks, db, tableId, baseTable, dstTable, aggrSummable, aggrUnsummable, aggInterval, duration); err != nil {
				return err
			}
		case MOD:
			if m.isModifyingFlags[orgID][tableId] {
				return fmt.Errorf(ERR_IS_MODIFYING, tableId.TableName())
			}
			log.Infof("mod rp tableId %d %s, dstTable %s", tableId, tableId.TableName(), dstTable)
			go func(id flow_metrics.MetricsTableID) {
				m.isModifyingFlags[orgID][id] = true
				if err := m.modTableMV(m.cks, id, db, dstTable, duration); err != nil {
					log.Warning(err)
				}
				m.isModifyingFlags[orgID][id] = false
			}(tableId)
		case DEL:
			if err := delTableMV(m.cks, tableId, db, dstTable); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupport action %d", action)
		}
	}
	return nil
}
