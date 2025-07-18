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
	"net"
	"strings"
	"unsafe"

	"github.com/ClickHouse/ch-go/proto"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("ckdb")

const DEFAULT_COLUMN_COUNT = 256

type CKColumnBlock interface {
	ToInput(input proto.Input) proto.Input
	Reset()
}

func AppendColNullable[T any](col *proto.ColNullable[T], v *T) {
	if v == nil {
		col.Append(proto.Null[T]())
	} else {
		col.Append(proto.NewNullable[T](*v))
	}
}

func AppendIPv6(col *proto.ColIPv6, ipv6 net.IP) {
	if len(ipv6) == 0 {
		col.Append(proto.IPv6{})
	} else if len(ipv6) == net.IPv6len {
		col.Append(*(*[16]byte)(unsafe.Pointer(&ipv6[0])))
	} else {
		var protoIPv6 [16]byte
		copy(protoIPv6[:], ipv6)
		col.Append(protoIPv6)
	}
}

func AppendColDateTime(col *proto.ColDateTime, t uint32) {
	col.AppendRaw(proto.DateTime(t))
}

func AppendColDateTime64Micro(col *proto.ColDateTime64, t int64) {
	if !col.PrecisionSet {
		col.WithPrecision(proto.PrecisionMicro)
	}
	col.AppendRaw(proto.DateTime64(t))
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
	ENUM8
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
	ENUM8:                     "Enum8(%s)",
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
	CodecZSTD:        "ZSTD(1)",
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
	IndexTokenbf
)

var indexTypeString = []string{
	IndexNone:        "",
	IndexMinmax:      "minmax",
	IndexSet:         "set(300)",
	IndexBloomfilter: "bloom_filter",
	IndexTokenbf:     "tokenbf_v1(32768, 3, 0)",
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

	EngineByconityOffset
	CnchMergeTree            = MergeTree + EngineByconityOffset
	CnchAggregatingMergeTree = AggregatingMergeTree + EngineByconityOffset
	CnchReplacingMergeTree   = ReplacingMergeTree + EngineByconityOffset
	CnchSummingMergeTree     = SummingMergeTree + EngineByconityOffset
)

var engineTypeString = []string{
	Distributed:                    "Distributed('%s', '%s', '%s', rand())", // %s %s %s 指代cluster名，数据库名，表名
	MergeTree:                      "MergeTree()",
	ReplicatedMergeTree:            "ReplicatedMergeTree('/clickhouse/tables/{shard}/%s/%s', '{replica}')", // 字符串参数表示zk的路径，shard和replica自动从clickhouse的macros读取, %s/%s分别指代数据库名和表名
	AggregatingMergeTree:           "AggregatingMergeTree()",
	ReplicatedAggregatingMergeTree: "ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/%s/%s', '{replica}')",
	ReplacingMergeTree:             "ReplacingMergeTree(%s)",
	SummingMergeTree:               "SummingMergeTree(%s)",

	CnchMergeTree:            "CnchMergeTree()",
	CnchAggregatingMergeTree: "CnchAggregatingMergeTree()",
	CnchReplacingMergeTree:   "CnchReplacingMergeTree(%s)",
	CnchSummingMergeTree:     "CnchSummingMergeTree(%s)",
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

type AggrType uint8

const (
	AggrNone AggrType = iota
	AggrSum
	AggrAvg
	AggrLast
	AggrLastAndSum
	AggrLastAndSumProfileValue
)

var aggrTypeString = []string{
	AggrNone:                   "",
	AggrSum:                    "sum",
	AggrAvg:                    "avg",
	AggrLast:                   "last",
	AggrLastAndSum:             "last and sum",
	AggrLastAndSumProfileValue: "last and sum profile value",
}

func (t AggrType) String() string {
	return aggrTypeString[t]
}

const (
	DF_STORAGE_POLICY     = "df_storage"
	DF_CLUSTER            = "df_cluster"
	DF_REPLICATED_CLUSTER = "df_replicated_cluster"
	DF_TIMEZONE           = "Asia/Shanghai"
	CKDBTypeClickhouse    = "clickhouse"
	CKDBTypeByconity      = "byconity"
)

type Column struct {
	Name     string     // 列名
	Type     ColumnType // 数据类型
	TypeArgs string
	Codec    CodecType // 压缩算法
	Index    IndexType // 二级索引
	Comment  string    // 列注释

	GroupBy            bool // 在AggregatingMergeTree表中用于group by的字段
	IgnoredInAggrTable bool // Whether to store in AggregatingMergeTree table
	Aggr               AggrType
}

func (c *Column) MakeModifyTimeZoneSQL(database, table, timeZone string) string {
	if timeZone == "" || timeZone == DF_TIMEZONE || !c.Type.HasDFTimeZone() {
		return ""
	}
	newTimeZoneType := strings.ReplaceAll(c.Type.String(), DF_TIMEZONE, timeZone)
	return fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY COLUMN %s %s", database, table, c.Name, newTimeZoneType)
}

func (c *Column) SetGroupBy() *Column {
	c.GroupBy = true
	return c
}

func (c *Column) SetIgnoredInAggrTable() *Column {
	c.IgnoredInAggrTable = true
	return c
}

func (c *Column) SetAggr(a AggrType) *Column {
	c.Aggr = a
	return c
}

func (c *Column) SetAggrLast() *Column {
	c.Aggr = AggrLast
	return c
}

func (c *Column) SetAggrLastAndSumProfileValue() *Column {
	c.Aggr = AggrLastAndSumProfileValue
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

func (c *Column) SetTypeArgs(args string) *Column {
	c.TypeArgs = args
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
	return &Column{name, t, "", codec, index, "", false, false, AggrNone}
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
