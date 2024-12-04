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

package ckdb

import (
	"fmt"
	"strings"
)

const (
	DEFAULT_ORG_ID    = 1
	INVALID_ORG_ID    = 0
	DEFAULT_TEAM_ID   = 1
	INVALID_TEAM_ID   = 0
	ORG_ID_LEN        = 4 // length of 'xxxx'
	ORG_ID_PREFIX_LEN = 5 // length of 'xxxx_'
	MAX_ORG_ID        = 1024
	AGGREGATION_1H    = "1h"
	AGGREGATION_1D    = "1d"
	DEFAULT_1H_TTL    = 24 * 30 // 30 day
	DEFAULT_1D_TTL    = 24 * 30 // 30 day
)

type AggregationInterval uint8

const (
	AggregationMinute AggregationInterval = iota
	AggregationHour
	AggregationDay
)

func (a AggregationInterval) String() string {
	switch a {
	case AggregationMinute:
		return "1m"
	case AggregationHour:
		return "1h"
	case AggregationDay:
		return "1d"
	default:
		return "unkunown aggregation interval"
	}
}

func (a AggregationInterval) BaseTable() string {
	switch a {
	case AggregationMinute:
		return "1s_local"
	case AggregationHour:
		return "1m_local"
	case AggregationDay:
		return "1h_agg"
	default:
		return "unkunown aggregation base table"
	}
}

func (a AggregationInterval) ByconityBaseTable() string {
	switch a {
	case AggregationMinute:
		return "1s"
	case AggregationHour, AggregationDay:
		return "1m"
	default:
		return "unkunown aggregation byconity base table"
	}
}

func (a AggregationInterval) PartitionBy() TimeFuncType {
	switch a {
	case AggregationMinute:
		return TimeFuncTwelveHour
	case AggregationHour:
		return TimeFuncWeek
	case AggregationDay:
		return TimeFuncYYYYMM
	default:
		return TimeFuncWeek
	}
}

func (a AggregationInterval) Aggregation() TimeFuncType {
	switch a {
	case AggregationMinute:
		return TimeFuncMinute
	case AggregationHour:
		return TimeFuncHour
	case AggregationDay:
		return TimeFuncDay
	default:
		return TimeFuncHour
	}
}

func IsDefaultOrgID(orgID uint16) bool {
	if orgID == DEFAULT_ORG_ID || orgID == INVALID_ORG_ID {
		return true
	}
	return false
}

func IsValidOrgID(orgID uint16) bool {
	if orgID == INVALID_ORG_ID || orgID > MAX_ORG_ID {
		return false
	}
	return true
}

func OrgDatabasePrefix(orgID uint16) string {
	if IsDefaultOrgID(orgID) {
		return ""
	}
	// format it as a 4-digit number. If there are less than 4 digits, fill the high bits with 0
	return fmt.Sprintf("%04d_", orgID)
}

const (
	METRICS_DB    = "flow_metrics"
	LOCAL_SUBFFIX = "_local"
)

type ColdStorage struct {
	Enabled   bool
	Type      DiskType
	Name      string
	TTLToMove int // after 'TTLToMove' hours, then move data to cold storage
}

func GetColdStorage(coldStorages map[string]*ColdStorage, db, table string) *ColdStorage {
	if coldStorage, ok := coldStorages[db+table]; ok {
		return coldStorage
	}

	if coldStorage, ok := coldStorages[db]; ok {
		return coldStorage
	}
	return &ColdStorage{}
}

type Table struct {
	Version         string       // 表版本，用于表结构变更时，做自动更新
	ID              uint8        // id
	Database        string       // 所属数据库名
	DBType          string       // clickhouse or byconity
	LocalName       string       // 本地表名
	GlobalName      string       // 全局表名
	Columns         []*Column    // 表列结构
	TimeKey         string       // 时间字段名，用来设置partition和ttl
	SummingKey      string       // When using SummingMergeEngine, this field is used for Summing aggregation
	TTL             int          // 数据默认保留时长。 单位:小时
	ColdStorage     ColdStorage  // 冷存储配置
	PartitionFunc   TimeFuncType // partition函数作用于Time,
	Cluster         string       // 对应的cluster
	StoragePolicy   string       // 存储策略
	Engine          EngineType   // 表引擎
	OrderKeys       []string     // 排序的key
	PrimaryKeyCount int          // 一级索引的key的个数, 从orderKeys中数前n个,
	Aggr1H1D        bool         // 是否创建 1h/1d 表
}

func (t *Table) OrgDatabase(orgID uint16) string {
	return OrgDatabasePrefix(orgID) + t.Database
}

func (t *Table) makeLocalTableCreateSQL(database string) string {
	columns := []string{}
	for _, c := range t.Columns {
		comment := ""
		// 把time字段的注释标记为表的version
		if c.Name == t.TimeKey {
			c.Comment = t.Version
		}
		if c.Comment != "" {
			comment = fmt.Sprintf("COMMENT '%s'", c.Comment)
		}
		codec := ""
		if c.Codec != CodecDefault {
			codec = fmt.Sprintf("CODEC(%s)", c.Codec.String())
		}

		columnType := c.Type.String()
		if c.TypeArgs != "" {
			columnType = fmt.Sprintf(c.Type.String(), c.TypeArgs)
		}
		columns = append(columns, fmt.Sprintf("`%s` %s %s %s", c.Name, columnType, comment, codec))

		if c.Index != IndexNone {
			columns = append(columns, fmt.Sprintf("INDEX %s_idx (%s) TYPE %s GRANULARITY 2", c.Name, c.Name, c.Index.String()))
		}
	}

	preload := ""
	if t.DBType == CKDBTypeByconity {
		if t.Engine < EngineByconityOffset {
			t.Engine = t.Engine + EngineByconityOffset
		}
		preload = ", parts_preload_level = 3" // enable preloading for the table, preload both metadata and some data
	}

	engine := t.Engine.String()
	if t.Engine == ReplicatedMergeTree || t.Engine == ReplicatedAggregatingMergeTree {
		engine = fmt.Sprintf(t.Engine.String(), t.Database, t.LocalName)
	} else if t.Engine == ReplacingMergeTree || t.Engine == CnchReplacingMergeTree {
		engine = fmt.Sprintf(t.Engine.String(), t.TimeKey)
	} else if t.Engine == SummingMergeTree || t.Engine == CnchSummingMergeTree {
		engine = fmt.Sprintf(t.Engine.String(), t.SummingKey)
	}

	partition := ""
	if t.PartitionFunc != TimeFuncNone {
		partition = fmt.Sprintf("PARTITION BY %s", t.PartitionFunc.String(t.TimeKey))
	}
	ttl := ""
	if t.TTL > 0 {
		ttl = fmt.Sprintf("TTL %s +  toIntervalHour(%d)", t.TimeKey, t.TTL)
		if t.ColdStorage.Enabled {
			ttl += fmt.Sprintf(", %s + toIntervalHour(%d) TO %s '%s'", t.TimeKey, t.ColdStorage.TTLToMove, t.ColdStorage.Type, t.ColdStorage.Name)
		}
	}

	createTable := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s.%s
(%s)
ENGINE = %s
PRIMARY KEY (%s)
ORDER BY (%s)
%s
%s
SETTINGS storage_policy = '%s', ttl_only_drop_parts = 1%s`,
		database, fmt.Sprintf("`%s`", t.LocalName),
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(t.OrderKeys, ","),
		partition,
		ttl,
		t.StoragePolicy,
		preload) // only for Byconity
	return createTable
}

func (t *Table) MakeLocalTableCreateSQL() string {
	if t.DBType == CKDBTypeByconity {
		return "SELECT VERSION()"
	}
	return t.makeLocalTableCreateSQL(t.Database)
}

func (t *Table) MakeOrgLocalTableCreateSQL(orgID uint16) string {
	if t.DBType == CKDBTypeByconity {
		return "SELECT VERSION()"
	}
	return t.makeLocalTableCreateSQL(t.OrgDatabase(orgID))
}

func (t *Table) makeGlobalTableCreateSQL(database string) string {
	if t.DBType == CKDBTypeByconity {
		t.LocalName = t.GlobalName
		return t.makeLocalTableCreateSQL(database)
	}
	engine := fmt.Sprintf(Distributed.String(), t.Cluster, database, t.LocalName)
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.`%s` AS %s.`%s` ENGINE=%s",
		database, t.GlobalName, database, t.LocalName, engine)
}

func (t *Table) MakeGlobalTableCreateSQL() string {
	return t.makeGlobalTableCreateSQL(t.Database)
}

func (t *Table) MakeOrgGlobalTableCreateSQL(orgID uint16) string {
	return t.makeGlobalTableCreateSQL(t.OrgDatabase(orgID))
}

func (t *Table) makePrepareTableInsertSQL(database string) string {
	if t.DBType == CKDBTypeByconity {
		t.LocalName = t.GlobalName
	}
	columns := []string{}
	values := []string{}
	for _, c := range t.Columns {
		columns = append(columns, c.Name)
		values = append(values, "?")
	}

	prepare := fmt.Sprintf("INSERT INTO %s.`%s` (%s) VALUES (%s)",
		database, t.LocalName,
		strings.Join(columns, ","),
		strings.Join(values, ","))

	return prepare
}

func (t *Table) MakePrepareTableInsertSQL() string {
	return t.makePrepareTableInsertSQL(t.Database)
}

func (t *Table) MakeOrgPrepareTableInsertSQL(orgID uint16) string {
	return t.makePrepareTableInsertSQL(t.OrgDatabase(orgID))
}

func stringSliceHas(items []string, item string) bool {
	for _, s := range items {
		if s == item {
			return true
		}
	}
	return false
}

func (t *Table) makeTTLString(duration int) string {
	if t.ColdStorage.Enabled {
		return fmt.Sprintf("%s + toIntervalHour(%d), %s +  toIntervalHour(%d) TO %s '%s'",
			t.TimeKey, duration,
			t.TimeKey, t.ColdStorage.TTLToMove, t.ColdStorage.Type, t.ColdStorage.Name)
	}
	return fmt.Sprintf("%s + toIntervalHour(%d)", t.TimeKey, duration)
}

func isUnsummable(column *Column) bool {
	if strings.HasSuffix(column.Name, "_max") ||
		column.Name == "direction_score" {
		return true
	}
	return false
}

func getAggr(column *Column) string {
	if isUnsummable(column) {
		return "avg"
	}
	return "sum"
}

func (t *Table) MakeAggrTableCreateSQL1H(orgID uint16) string {
	return t.MakeAggrTableCreateSQL(orgID, AggregationHour, DEFAULT_1H_TTL)
}

func (t *Table) MakeAggrMVTableCreateSQL1H(orgID uint16) string {
	return t.MakeAggrMVTableCreateSQL(orgID, AggregationHour)
}

func (t *Table) MakeAggrLocalTableCreateSQL1H(orgID uint16) string {
	return t.MakeAggrLocalTableCreateSQL(orgID, AggregationHour)
}

func (t *Table) MakeAggrGlobalTableCreateSQL1H(orgID uint16) string {
	return t.MakeAggrGlobalTableCreateSQL(orgID, AggregationHour)
}

func (t *Table) MakeAggrTableCreateSQL1D(orgID uint16) string {
	return t.MakeAggrTableCreateSQL(orgID, AggregationDay, DEFAULT_1D_TTL)
}

func (t *Table) MakeAggrMVTableCreateSQL1D(orgID uint16) string {
	return t.MakeAggrMVTableCreateSQL(orgID, AggregationDay)
}

func (t *Table) MakeAggrLocalTableCreateSQL1D(orgID uint16) string {
	return t.MakeAggrLocalTableCreateSQL(orgID, AggregationDay)
}

func (t *Table) MakeAggrGlobalTableCreateSQL1D(orgID uint16) string {
	return t.MakeAggrGlobalTableCreateSQL(orgID, AggregationDay)
}

func (t *Table) tablePrefix() string {
	return strings.Split(t.GlobalName, ".")[0]
}

func (t *Table) MakeAggrTableCreateSQL(orgID uint16, aggrInterval AggregationInterval, ttlHour int) string {
	tableAgg := fmt.Sprintf("%s.`%s.%s_agg`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	columns := []string{}
	orderKeys := t.OrderKeys
	for _, c := range t.Columns {
		// ignore fields starting with '_', such as _tid, _id
		if strings.HasPrefix(c.Name, "_") {
			continue
		}
		codec := ""
		if c.Codec != CodecDefault {
			codec = fmt.Sprintf("codec(%s)", c.Codec.String())
		}

		if c.Name == t.TimeKey {
			c.Comment = t.Version
		}

		if c.GroupBy {
			comment := ""
			if c.Comment != "" {
				comment = fmt.Sprintf("COMMENT '%s'", c.Comment)
			}
			columns = append(columns, fmt.Sprintf("%s %s %s %s", c.Name, c.Type.String(), comment, codec))
		} else {
			columns = append(columns, fmt.Sprintf("%s__agg AggregateFunction(%s, %s)", c.Name, getAggr(c), c.Type.String()))
		}
	}

	engine := AggregatingMergeTree.String()
	if t.DBType == CKDBTypeByconity {
		engine = CnchAggregatingMergeTree.String()
	}

	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s
				   (%s)
				   ENGINE=%s
				   PRIMARY KEY (%s)
				   ORDER BY (%s)
				   PARTITION BY %s
				   TTL %s
				   SETTINGS storage_policy = '%s'`,
		tableAgg,
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(orderKeys, ","), // 以order by的字段排序, 相同的做聚合
		aggrInterval.PartitionBy().String(t.TimeKey),
		t.makeTTLString(ttlHour),
		t.StoragePolicy)
}

func (t *Table) MakeAggrMVTableCreateSQL(orgID uint16, aggrInterval AggregationInterval) string {
	tableMv := fmt.Sprintf("%s.`%s.%s_mv`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	tableAgg := fmt.Sprintf("%s.`%s.%s_agg`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	tableBase := fmt.Sprintf("%s.`%s.%s`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.BaseTable())

	if t.DBType == CKDBTypeByconity {
		tableBase = fmt.Sprintf("%s.`%s.%s`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.ByconityBaseTable())
	}

	groupKeys := t.OrderKeys
	columns := []string{}
	for _, c := range t.Columns {
		if strings.HasPrefix(c.Name, "_") {
			continue
		}
		if c.GroupBy {
			if c.Name == t.TimeKey {
				columns = append(columns, fmt.Sprintf("%s AS %s", aggrInterval.Aggregation().String(t.TimeKey), t.TimeKey))
			} else {
				columns = append(columns, c.Name)
			}
			if !stringSliceHas(groupKeys, c.Name) {
				groupKeys = append(groupKeys, c.Name)
			}
		} else {
			if strings.Contains(tableBase, "_agg") {
				columns = append(columns, fmt.Sprintf("%sMergeState(%s__agg) AS %s__agg", getAggr(c), c.Name, c.Name))
			} else {
				columns = append(columns, fmt.Sprintf("%sState(%s) AS %s__agg", getAggr(c), c.Name, c.Name))
			}
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

func (t *Table) MakeAggrLocalTableCreateSQL(orgID uint16, aggrInterval AggregationInterval) string {
	tableAgg := fmt.Sprintf("%s.`%s.%s_agg`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	tableLocal := fmt.Sprintf("%s.`%s.%s_local`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	if t.DBType == CKDBTypeByconity {
		tableLocal = fmt.Sprintf("%s.`%s.%s`", t.OrgDatabase(orgID), t.tablePrefix(), aggrInterval.String())
	}

	columns := []string{}
	groupKeys := t.OrderKeys
	for _, c := range t.Columns {
		if strings.HasPrefix(c.Name, "_") {
			continue
		}
		if c.GroupBy {
			columns = append(columns, c.Name)
			if !stringSliceHas(groupKeys, c.Name) {
				groupKeys = append(groupKeys, c.Name)
			}
		} else {
			columns = append(columns, fmt.Sprintf("finalizeAggregation(%s__agg) AS %s", c.Name, c.Name))
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

func (t *Table) MakeAggrGlobalTableCreateSQL(orgID uint16, aggrInterval AggregationInterval) string {
	if t.DBType == CKDBTypeByconity {
		return "SELECT VERSION()"
	}
	tableGlobal := fmt.Sprintf("%s.%s", t.tablePrefix(), aggrInterval.String())
	tableLocal := fmt.Sprintf("%s.%s_local", t.tablePrefix(), aggrInterval.String())

	engine := fmt.Sprintf(Distributed.String(), t.Cluster, t.OrgDatabase(orgID), tableLocal)
	createTable := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.`%s` AS %s.`%s` ENGINE = %s",
		t.OrgDatabase(orgID), tableGlobal, t.OrgDatabase(orgID), tableLocal, engine)
	return createTable
}
