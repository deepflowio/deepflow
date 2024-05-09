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
)

func IsDefaultOrgID(orgID uint16) bool {
	if orgID == DEFAULT_ORG_ID || orgID == INVALID_ORG_ID {
		return true
	}
	return false
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
		columns = append(columns, fmt.Sprintf("`%s` %s %s %s", c.Name, c.Type.String(), comment, codec))

		if c.Index != IndexNone {
			columns = append(columns, fmt.Sprintf("INDEX %s_idx (%s) TYPE %s GRANULARITY 3", c.Name, c.Name, c.Index.String()))
		}
	}

	engine := t.Engine.String()
	if t.Engine == ReplicatedMergeTree || t.Engine == ReplicatedAggregatingMergeTree {
		engine = fmt.Sprintf(t.Engine.String(), t.Database, t.LocalName)
	} else if t.Engine == ReplacingMergeTree {
		engine = fmt.Sprintf(t.Engine.String(), t.TimeKey)
	} else if t.Engine == SummingMergeTree {
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
SETTINGS storage_policy = '%s'`,
		database, fmt.Sprintf("`%s`", t.LocalName),
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(t.OrderKeys, ","),
		partition,
		ttl,
		t.StoragePolicy)
	return createTable
}

func (t *Table) MakeLocalTableCreateSQL() string {
	return t.makeLocalTableCreateSQL(t.Database)
}

func (t *Table) MakeOrgLocalTableCreateSQL(orgID uint16) string {
	return t.makeLocalTableCreateSQL(t.OrgDatabase(orgID))
}

func (t *Table) makeGlobalTableCreateSQL(database string) string {
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

// database 'xxxx_deepflow_system' adds 'deepflow_system' view pointing to the 'deepflow_system_agent' and 'deepflow_system_server' table
func (t *Table) MakeViewsCreateSQLForDeepflowSystem(orgID uint16) []string {
	createViewSqls := []string{}
	if t.Database == "deepflow_system" && t.GlobalName == "deepflow_system_server" {
		// recreate table deepflow_system.deepflow_system, for upgrade
		if orgID == DEFAULT_ORG_ID || orgID == INVALID_ORG_ID {
			dropTable := "DROP TABLE IF EXISTS deepflow_system.deepflow_system"
			createViewSqls = append(createViewSqls, dropTable)
		}
		deepflowSystemServerView := fmt.Sprintf("CREATE VIEW IF NOT EXISTS %s.`%s` AS SELECT * FROM %s.`%s` UNION ALL SELECT * FROM deepflow_system.deepflow_system_server",
			t.OrgDatabase(orgID), "deepflow_system", t.OrgDatabase(orgID), "deepflow_system_agent")
		createViewSqls = append(createViewSqls, deepflowSystemServerView)
	}
	if t.Database == "flow_tag" && t.GlobalName == "deepflow_system_server_custom_field" {
		// recreate table flow_tag.deepflow_system_custom_field, for upgrade
		if orgID == DEFAULT_ORG_ID || orgID == INVALID_ORG_ID {
			dropTable := "DROP TABLE IF EXISTS flow_tag.deepflow_system_custom_field"
			createViewSqls = append(createViewSqls, dropTable)
		}
		flowTagFieldView := fmt.Sprintf("CREATE VIEW IF NOT EXISTS %s.`%s` AS SELECT * FROM %s.`%s` UNION ALL SELECT * FROM flow_tag.deepflow_system_server_custom_field",
			OrgDatabasePrefix(orgID)+"flow_tag", "deepflow_system_custom_field", OrgDatabasePrefix(orgID)+"flow_tag", "deepflow_system_agent_custom_field")
		createViewSqls = append(createViewSqls, flowTagFieldView)
	}
	if t.Database == "flow_tag" && t.GlobalName == "deepflow_system_server_custom_field_value" {
		// recreate table flow_tag.deepflow_system_custom_field_value, for upgrade
		if orgID == DEFAULT_ORG_ID || orgID == INVALID_ORG_ID {
			dropTable := "DROP TABLE IF EXISTS flow_tag.deepflow_system_custom_field_value"
			createViewSqls = append(createViewSqls, dropTable)
		}
		flowTagFieldValueView := fmt.Sprintf("CREATE VIEW IF NOT EXISTS %s.`%s` AS SELECT * FROM %s.`%s` UNION ALL SELECT * FROM flow_tag.deepflow_system_server_custom_field_value",
			OrgDatabasePrefix(orgID)+"flow_tag", "deepflow_system_custom_field_value", OrgDatabasePrefix(orgID)+"flow_tag", "deepflow_system_agent_custom_field_value")
		createViewSqls = append(createViewSqls, flowTagFieldValueView)
	}
	return createViewSqls
}

func (t *Table) makePrepareTableInsertSQL(database string) string {
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
