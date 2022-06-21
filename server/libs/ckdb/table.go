package ckdb

import (
	"fmt"
	"strings"
)

const (
	METRICS_DB    = "flow_metrics"
	LOCAL_SUBFFIX = "_local"
)

type Table struct {
	Version         string       // 表版本，用于表结构变更时，做自动更新
	ID              uint8        // id
	Database        string       // 所属数据库名
	LocalName       string       // 本地表名
	GlobalName      string       // 全局表名
	Columns         []*Column    // 表列结构
	TimeKey         string       // 时间字段名，用来设置partition和ttl
	TTL             int          // 数据默认保留时长。 单位:天
	PartitionFunc   TimeFuncType // partition函数作用于Time,
	Cluster         ClusterType  // 高可用和非高可用表，对应的cluster不同
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
	}

	createTable := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s.%s
(%s)
ENGINE = %s
PRIMARY KEY (%s)
ORDER BY (%s)
PARTITION BY %s
TTL %s +  toIntervalDay(%d)
SETTINGS storage_policy = '%s'`,
		t.Database, fmt.Sprintf("`%s`", t.LocalName),
		strings.Join(columns, ",\n"),
		engine,
		strings.Join(t.OrderKeys[:t.PrimaryKeyCount], ","),
		strings.Join(t.OrderKeys, ","),
		t.PartitionFunc.String(t.TimeKey),
		t.TimeKey, t.TTL,
		DF_STORAGE_POLICY)
	return createTable
}

func (t *Table) MakeGlobalTableCreateSQL() string {
	engine := fmt.Sprintf(Distributed.String(), t.Cluster.String(), t.Database, t.LocalName)
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
