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

package ckdb

import (
	"fmt"
	"strings"
)

const (
	METRICS_DB    = "flow_metrics"
	LOCAL_SUBFFIX = "_local"
)

type ColdStorage struct {
	Enabled   bool
	Type      DiskType
	Name      string
	TTLToMove int // after 'TTLToMove' days, then move data to cold storage
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
	TTL             int          // 数据默认保留时长。 单位:天
	ColdStorage     ColdStorage  // 冷存储配置
	PartitionFunc   TimeFuncType // partition函数作用于Time,
	Cluster         string       // 对应的cluster
	StoragePolicy   string       // 存储策略
	Engine          EngineType   // 表引擎
	OrderKeys       []string     // 排序的key
	PrimaryKeyCount int          // 一级索引的key的个数, 从orderKeys中数前n个,
}

func (t *Table) MakeLocalTableCreateSQL() string {
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
		ttl = fmt.Sprintf("TTL %s +  toIntervalDay(%d)", t.TimeKey, t.TTL)
		if t.ColdStorage.Enabled {
			ttl += fmt.Sprintf(", %s + toIntervalDay(%d) TO %s '%s'", t.TimeKey, t.ColdStorage.TTLToMove, t.ColdStorage.Type, t.ColdStorage.Name)
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
		t.Database, fmt.Sprintf("`%s`", t.LocalName),
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(t.OrderKeys, ","),
		partition,
		ttl,
		t.StoragePolicy)
	return createTable
}

func (t *Table) MakeGlobalTableCreateSQL() string {
	engine := fmt.Sprintf(Distributed.String(), t.Cluster, t.Database, t.LocalName)
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.`%s` AS %s.`%s` ENGINE=%s",
		t.Database, t.GlobalName, t.Database, t.LocalName, engine)
}

func (t *Table) MakePrepareTableInsertSQL() string {
	columns := []string{}
	values := []string{}
	for _, c := range t.Columns {
		columns = append(columns, c.Name)
		values = append(values, "?")
	}

	prepare := fmt.Sprintf("INSERT INTO %s.`%s` (%s) VALUES (%s)",
		t.Database, t.LocalName,
		strings.Join(columns, ","),
		strings.Join(values, ","))

	return prepare
}
