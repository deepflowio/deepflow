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

package ckdb

import (
	"fmt"
	"net"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("ckdb")

const DEFAULT_COLUMN_COUNT = 256

type Block struct {
	batch driver.Batch
	items []interface{}
}

func NewBlock(batch driver.Batch) *Block {
	return &Block{
		batch: batch,
		items: make([]interface{}, 0, DEFAULT_COLUMN_COUNT),
	}
}

func (b *Block) WriteAll() error {
	err := b.batch.Append(b.items...)
	b.items = b.items[:0]
	return err
}

func (b *Block) Send() error {
	return b.batch.Send()
}

func (b *Block) Write(v ...interface{}) {
	b.items = append(b.items, v...)
}

func (b *Block) WriteBool(v bool) {
	b.items = append(b.items, utils.Bool2UInt8(v))
}

func (b *Block) WriteDateTime(v uint32) {
	b.items = append(b.items, v)
}

func (b *Block) WriteIPv4(v uint32) {
	b.items = append(b.items, utils.IpFromUint32(v))
}

func (b *Block) WriteIPv6(v net.IP) {
	if len(v) == 0 {
		v = net.IPv6zero
	}
	b.items = append(b.items, v)
}

type ColumnType uint8

const (
	UInt64 ColumnType = iota
	UInt64Nullable
	UInt32
	UInt32Nullable
	UInt16
	UInt16Nullable
	UInt8
	UInt8Nullable
	Int64
	Int64Nullable
	Int32
	Int32Nullable
	Int16
	Int16Nullable
	Int8
	Int8Nullable
	Float64
	Float64Nullable
	String
	IPv6
	IPv4
	ArrayString
	ArrayUInt8
	ArrayUInt16
	ArrayUInt32
	ArrayInt64
	ArrayFloat64
	DateTime
	DateTime64
	DateTime64ms
	DateTime64us
	FixString8
	LowCardinalityString
	ArrayLowCardinalityString
)

var cloumnTypeString = []string{
	UInt64:                    "UInt64",
	UInt64Nullable:            "Nullable(UInt64)",
	UInt32:                    "UInt32",
	UInt32Nullable:            "Nullable(UInt32)",
	UInt16:                    "UInt16",
	UInt16Nullable:            "Nullable(UInt16)",
	UInt8:                     "UInt8",
	UInt8Nullable:             "Nullable(UInt8)",
	Int64:                     "Int64",
	Int64Nullable:             "Nullable(Int64)",
	Int32:                     "Int32",
	Int32Nullable:             "Nullable(Int32)",
	Int16:                     "Int16",
	Int16Nullable:             "Nullable(Int16)",
	Int8:                      "Int8",
	Int8Nullable:              "Nullable(Int8)",
	Float64:                   "Float64",
	Float64Nullable:           "Nullable(Float64)",
	String:                    "String",
	IPv6:                      "IPv6",
	IPv4:                      "IPv4",
	ArrayString:               "Array(String)",
	ArrayUInt8:                "Array(UInt8)",
	ArrayUInt16:               "Array(UInt16)",
	ArrayUInt32:               "Array(UInt32)",
	ArrayInt64:                "Array(Int64)",
	ArrayFloat64:              "Array(Float64)",
	DateTime:                  "DateTime('" + DF_TIMEZONE + "')",
	DateTime64:                "DateTime64(0, '" + DF_TIMEZONE + "')",
	DateTime64ms:              "DateTime64(3, '" + DF_TIMEZONE + "')",
	DateTime64us:              "DateTime64(6, '" + DF_TIMEZONE + "')",
	FixString8:                "FixedString(8)",
	LowCardinalityString:      "LowCardinality(String)",
	ArrayLowCardinalityString: "Array(LowCardinality(String))",
}

func (t ColumnType) HasDFTimeZone() bool {
	return strings.Contains(t.String(), DF_TIMEZONE)
}

func (t ColumnType) String() string {
	return cloumnTypeString[t]
}

type CodecType uint8

const (
	CodecDefault CodecType = iota // lz4
	CodecLZ4
	CodecLZ4HC
	CodecZSTD
	CodecT64
	CodecDelta
	CodecDoubleDelta
	CodecGorilla
	CodecNone
)

var codecTypeString = []string{
	CodecDefault:     "",
	CodecLZ4:         "LZ4",
	CodecLZ4HC:       "LZ4HC",
	CodecZSTD:        "ZSTD",
	CodecT64:         "T64",
	CodecDelta:       "Delta",
	CodecDoubleDelta: "DoubleDelta",
	CodecGorilla:     "Gorilla",
	CodecNone:        "None",
}

func (t CodecType) String() string {
	return codecTypeString[t]
}

type IndexType uint8

const (
	IndexNone IndexType = iota
	IndexMinmax
	IndexSet
	IndexBloomfilter
)

var indexTypeString = []string{
	IndexNone:        "",
	IndexMinmax:      "minmax",
	IndexSet:         "set(300)",
	IndexBloomfilter: "bloom_filter",
}

func (t IndexType) String() string {
	return indexTypeString[t]
}

type TimeFuncType uint8

const (
	TimeFuncNone TimeFuncType = iota
	TimeFuncMinute
	TimeFuncTenMinute
	TimeFuncHour
	TimeFuncTwoHour
	TimeFuncFourHour
	TimeFuncTwelveHour
	TimeFuncDay
	TimeFuncWeek
	TimeFuncMonth
	TimeFuncYYYYMM
	TimeFuncYYYYMMDD
)

var timeFuncTypeString = []string{
	TimeFuncNone:       "%s",
	TimeFuncMinute:     "toStartOfMinute(%s)", // %s指代函数作用于的字段名
	TimeFuncTenMinute:  "toStartOfTenMinute(%s)",
	TimeFuncHour:       "toStartOfHour(%s)",
	TimeFuncTwoHour:    "toStartOfInterval(%s, INTERVAL 2 hour)",
	TimeFuncFourHour:   "toStartOfInterval(%s, INTERVAL 4 hour)",
	TimeFuncTwelveHour: "toStartOfInterval(%s, INTERVAL 12 hour)",
	TimeFuncDay:        "toStartOfDay(%s)",
	TimeFuncWeek:       "toStartOfWeek(%s)",
	TimeFuncMonth:      "toStartOfMonth(%s)",
	TimeFuncYYYYMM:     "toYYYYMM(%s)",
	TimeFuncYYYYMMDD:   "toYYYYMMDD(%s)",
}

func (t TimeFuncType) String(timeKey string) string {
	return fmt.Sprintf(timeFuncTypeString[t], timeKey)
}

type EngineType uint8

const (
	Distributed EngineType = iota
	MergeTree
	ReplicatedMergeTree
	AggregatingMergeTree
	ReplicatedAggregatingMergeTree
	ReplacingMergeTree
	SummingMergeTree
)

var engineTypeString = []string{
	Distributed:                    "Distributed('%s', '%s', '%s', rand())", // %s %s %s 指代cluster名，数据库名，表名
	MergeTree:                      "MergeTree()",
	ReplicatedMergeTree:            "ReplicatedMergeTree('/clickhouse/tables/{shard}/%s/%s', '{replica}')", // 字符串参数表示zk的路径，shard和replica自动从clickhouse的macros读取, %s/%s分别指代数据库名和表名
	AggregatingMergeTree:           "AggregatingMergeTree()",
	ReplicatedAggregatingMergeTree: "ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/%s/%s', '{replica}')",
	ReplacingMergeTree:             "ReplacingMergeTree(%s)",
	SummingMergeTree:               "SummingMergeTree(%s)",
}

func (t EngineType) String() string {
	return engineTypeString[t]
}

type DiskType uint8

const (
	Volume DiskType = iota
	Disk
)

func (t DiskType) String() string {
	switch t {
	case Volume:
		return "VOLUME"
	case Disk:
		return "DISK"
	}
	return "Unknown"
}

const (
	DF_STORAGE_POLICY     = "df_storage"
	DF_CLUSTER            = "df_cluster"
	DF_REPLICATED_CLUSTER = "df_replicated_cluster"
	DF_TIMEZONE           = "Asia/Shanghai"
)

type Column struct {
	Name    string     // 列名
	Type    ColumnType // 数据类型
	Codec   CodecType  // 压缩算法
	Index   IndexType  // 二级索引
	GroupBy bool       // 在AggregatingMergeTree表中用于group by的字段
	Comment string     // 列注释
}

func (c *Column) MakeModifyTimeZoneSQL(database, table, timeZone string) string {
	if timeZone == "" || !c.Type.HasDFTimeZone() {
		return ""
	}
	newTimeZoneType := strings.ReplaceAll(c.Type.String(), DF_TIMEZONE, timeZone)
	return fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY COLUMN %s %s", database, table, c.Name, newTimeZoneType)
}

func (c *Column) SetGroupBy() *Column {
	c.GroupBy = true
	return c
}

func (c *Column) SetCodec(ct CodecType) *Column {
	c.Codec = ct
	return c
}

func (c *Column) SetIndex(i IndexType) *Column {
	c.Index = i
	return c
}

func (c *Column) SetComment(comment string) *Column {
	c.Comment = comment
	return c
}

func NewColumn(name string, t ColumnType) *Column {
	index := IndexNone
	codec := CodecDefault
	switch t {
	case UInt8: // u8默认设置set的二级索引
		index = IndexSet
	case UInt16, UInt32, Int32, IPv4, IPv6, ArrayUInt16: // 默认设置minmax的二级索引
		index = IndexMinmax
	case UInt64, Int64:
		codec = CodecT64
		index = IndexMinmax
	case DateTime, DateTime64ms, DateTime64us:
		codec = CodecDoubleDelta
		index = IndexMinmax // 时间默认设置minmax的二级索引
	case Float64:
		codec = CodecGorilla
		index = IndexMinmax
	}
	return &Column{name, t, codec, index, false, ""}
}

func NewColumnWithGroupBy(name string, t ColumnType) *Column {
	return NewColumn(name, t).SetGroupBy()
}

func NewColumns(names []string, t ColumnType) []*Column {
	columns := make([]*Column, 0, len(names))
	for _, name := range names {
		columns = append(columns, NewColumn(name, t))
	}
	return columns
}

// nameComments: 需要同时创建的列列表，列表元素是长度为2的字符串数组, 第一个元素是列名，第二个是注释内容
func NewColumnsWithComment(nameComments [][2]string, t ColumnType) []*Column {
	columns := make([]*Column, 0, len(nameComments))
	for _, nameComment := range nameComments {
		columns = append(columns, NewColumn(nameComment[0], t).SetComment(nameComment[1]))
	}
	return columns
}
