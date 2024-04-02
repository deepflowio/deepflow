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
	"strings"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
)

const (
	ORIGIN_TABLE_1M = "1m"
	ORIGIN_TABLE_1S = "1s"
	NETWORK         = "network"
	APPLICATION     = "application"
	TRAFFIC_POLICY  = "traffic_policy"

	ERR_IS_MODIFYING = "Modifying the retention time (%s), please try again later"
)

type DatasourceModifiedOnly string
type DatasourceInfo struct {
	ID     int
	DB     string
	Tables []string
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
	EVENT_ALARM_EVENT                        = "event.alarm_event"
	PROFILE                                  = "profile.in_process"
)

var DatasourceModifiedOnlyIDMap = map[DatasourceModifiedOnly]DatasourceInfo{
	DEEPFLOW_SYSTEM:   {int(flow_metrics.METRICS_TABLE_ID_MAX) + 1, "deepflow_system", []string{"deepflow_system"}},
	L4_FLOW_LOG:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 2, "flow_log", []string{"l4_flow_log"}},
	L7_FLOW_LOG:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 3, "flow_log", []string{"l7_flow_log"}},
	L4_PACKET:         {int(flow_metrics.METRICS_TABLE_ID_MAX) + 4, "flow_log", []string{"l4_packet"}},
	L7_PACKET:         {int(flow_metrics.METRICS_TABLE_ID_MAX) + 5, "flow_log", []string{"l7_packet"}},
	EXT_METRICS:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 6, "ext_metrics", []string{"metrics"}},
	PROMETHEUS:        {int(flow_metrics.METRICS_TABLE_ID_MAX) + 7, "prometheus", []string{"samples"}},
	EVENT_EVENT:       {int(flow_metrics.METRICS_TABLE_ID_MAX) + 8, "event", []string{"event"}},
	EVENT_PERF_EVENT:  {int(flow_metrics.METRICS_TABLE_ID_MAX) + 9, "event", []string{"perf_event"}},
	EVENT_ALARM_EVENT: {int(flow_metrics.METRICS_TABLE_ID_MAX) + 10, "event", []string{"alarm_event"}},
	PROFILE:           {int(flow_metrics.METRICS_TABLE_ID_MAX) + 11, "profile", []string{"in_process"}},
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
}

// 对于unsumable的sum列使用max,min聚合时, count列取相应的max,min列的值
var unsummableFieldsMap = map[string]struct{}{
	"rtt_sum":        {},
	"rtt_client_sum": {},
	"rtt_server_sum": {},
	"srt_sum":        {},
	"art_sum":        {},
	"rrt_sum":        {},

	"rtt_count":        {},
	"rtt_client_count": {},
	"rtt_server_count": {},
	"srt_count":        {},
	"art_count":        {},
	"rrt_count":        {},
}

func getColumnString(column *ckdb.Column, aggrSummable, aggrUnsummable string, t TableType) string {
	_, isUnsummable := unsummableFieldsMap[column.Name]
	isMaxMinAggr := (aggrUnsummable == aggrStrings[MAX]) || (aggrUnsummable == aggrStrings[MIN])
	_, isUnsummableMax := unsummableMaxFieldsMap[column.Name]

	// count字段的max,min聚合
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
			// 例如： argMaxMerge(rtt_count__agg) as rtt_count,
			return fmt.Sprintf("%sMerge(%s__%s) AS %s", aggrFunc, column.Name, AGG.String(), column.Name)
		}
	} else {
		// 普通的非累加和聚合和count字段的非max,min聚合和可累加的字段的聚合
		aggr := aggrSummable
		if isUnsummableMax || isUnsummable {
			aggr = aggrUnsummable
		}
		switch t {
		case AGG:
			return fmt.Sprintf("%s__%s AggregateFunction(%s, %s)", column.Name, t.String(), aggr, column.Type.String())
		case MV:
			return fmt.Sprintf("%sState(%s) AS %s__%s", aggr, column.Name, column.Name, AGG.String())
		case LOCAL:
			return fmt.Sprintf("%sMerge(%s__%s) AS %s", aggr, column.Name, AGG.String(), column.Name)
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
		return fmt.Sprintf("%s.`%s_%s`", db, tableId.TableName(), t.String())
	}
	if len(t.String()) == 0 {
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
			GROUP BY (%s)
			ORDER BY (%s)`,
		tableMv, tableAgg,
		strings.Join(columns, ",\n"),
		tableBase,
		strings.Join(groupKeys, ","),
		strings.Join(t.OrderKeys, ","))
}

func MakeCreateTableLocal(t *ckdb.Table, db, dstTable, aggrSummable, aggrUnsummable string) string {
	tableAgg := getMetricsTableName(t.ID, db, dstTable, AGG)
	tableLocal := getMetricsTableName(t.ID, db, dstTable, LOCAL)

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
FROM %s
GROUP BY %s`,
		tableLocal,
		strings.Join(columns, ",\n"),
		tableAgg,
		strings.Join(groupKeys, ","))
}

func MakeGlobalTableCreateSQL(t *ckdb.Table, db, dstTable string) string {
	tableGlobal := getMetricsTableName(t.ID, db, dstTable, GLOBAL)
	tableLocal := getMetricsTableName(t.ID, db, dstTable, LOCAL)
	tablePrefix := strings.Split(t.GlobalName, ".")[0]
	engine := fmt.Sprintf(ckdb.Distributed.String(), t.Cluster, db, tablePrefix+"."+dstTable+"_"+LOCAL.String())

	createTable := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s AS %s ENGINE = %s",
		tableGlobal, tableLocal, engine)
	return createTable
}

func (m *DatasourceManager) getMetricsTable(id flow_metrics.MetricsTableID) *ckdb.Table {
	return flow_metrics.GetMetricsTables(ckdb.MergeTree, basecommon.CK_VERSION, m.ckdbCluster, m.ckdbStoragePolicy, 7, 1, 7, 1, m.ckdbColdStorages)[id]
}

func (m *DatasourceManager) createTableMV(cks basecommon.DBs, db string, tableId flow_metrics.MetricsTableID, baseTable, dstTable, aggrSummable, aggrUnsummable string, aggInterval IntervalEnum, duration int) error {
	table := m.getMetricsTable(tableId)
	if baseTable != ORIGIN_TABLE_1M && baseTable != ORIGIN_TABLE_1S {
		return fmt.Errorf("Only support base datasource 1s,1m")
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

func (m *DatasourceManager) modTableTTL(cks basecommon.DBs, db, table string, duration int) error {
	tableLocal := fmt.Sprintf("%s.%s_%s", db, table, LOCAL)
	modTable := fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s",
		tableLocal, m.makeTTLString("time", db, table, duration))
	_, err := cks.ExecParallel(modTable)
	return err
}

func (m *DatasourceManager) Handle(orgID int, action ActionEnum, dbGroup, baseTable, dstTable, aggrSummable, aggrUnsummable string, interval, duration int) error {
	if len(m.ckAddrs) == 0 {
		return fmt.Errorf("ck addrs is empty")
	}

	if IsModifiedOnlyDatasource(dbGroup) && action == MOD {
		datasoureInfo := DatasourceModifiedOnly(dbGroup).DatasourceInfo()
		datasourceId := datasoureInfo.ID
		db := ckdb.OrgDatabasePrefix(uint16(orgID)) + datasoureInfo.DB
		tables := datasoureInfo.Tables

		cks, err := basecommon.NewCKConnections(m.ckAddrs, m.user, m.password)
		if err != nil {
			log.Error(err)
			return err
		}
		if m.isModifyingFlags[datasourceId] {
			return fmt.Errorf(ERR_IS_MODIFYING, dbGroup)
		}
		go func(tableNames []string, id int) {
			m.isModifyingFlags[id] = true
			for _, tableName := range tableNames {
				if err := m.modTableTTL(cks, db, tableName, duration); err != nil {
					log.Info(err)
				}
			}
			m.isModifyingFlags[id] = false
			cks.Close()
		}(tables, datasourceId)

		return nil
	}

	cks, err := basecommon.NewCKConnections(m.ckAddrs, m.user, m.password)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cks.Close()

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
			if err := m.createTableMV(cks, db, tableId, baseTable, dstTable, aggrSummable, aggrUnsummable, aggInterval, duration); err != nil {
				return err
			}
		case MOD:
			if m.isModifyingFlags[tableId] {
				return fmt.Errorf(ERR_IS_MODIFYING, tableId.TableName())
			}
			log.Infof("mod rp tableId %d %s, dstTable %s", tableId, tableId.TableName(), dstTable)
			go func(id flow_metrics.MetricsTableID) {
				cks, err := basecommon.NewCKConnections(m.ckAddrs, m.user, m.password)
				if err != nil {
					log.Error(err)
					return
				}
				defer cks.Close()
				m.isModifyingFlags[id] = true
				if err := m.modTableMV(cks, id, db, dstTable, duration); err != nil {
					log.Warning(err)
				}
				m.isModifyingFlags[id] = false
			}(tableId)
		case DEL:
			if err := delTableMV(cks, tableId, db, dstTable); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupport action %d", action)
		}
	}
	return nil
}
