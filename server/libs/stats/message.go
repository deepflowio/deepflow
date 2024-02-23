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

package stats

import (
	"errors"
	"unsafe"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	DATABASE = "telegraf"
)

type ValueType uint8

const (
	TypeInt64 ValueType = iota
	TypeFloat64
)

type Tag struct {
	Key   string
	Value string
}

type Field struct {
	Key   string
	Type  ValueType
	Value int64
}

type DFStats struct {
	Time      uint32
	TableName string
	Tags      []Tag
	Fields    []Field
}

// 用来区分该统计属于哪个表，取表名，tag，field 的hash，返回uint64
func (s *DFStats) Key() uint64 {
	base := utils.DJBHash(31, s.TableName)
	for _, tag := range s.Tags {
		base = utils.DJBHash(base, tag.Key)
	}
	for _, field := range s.Fields {
		base = utils.DJBHash(base, field.Key)
	}
	return base
}

func (s *DFStats) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(s.Time)
	encoder.WriteString255(s.TableName)

	encoder.WriteU8(byte(len(s.Tags)))
	for _, tag := range s.Tags {
		encoder.WriteString255(tag.Key)
		encoder.WriteString255(tag.Value)
	}

	encoder.WriteU8(byte(len(s.Fields)))
	for _, field := range s.Fields {
		encoder.WriteString255(field.Key)
		encoder.WriteU8(uint8(field.Type))
		encoder.WriteVarintU64(uint64(field.Value))
	}
}

func Decode(decoder *codec.SimpleDecoder) (*DFStats, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}
	s := AcquireDFStats()
	s.Time = decoder.ReadU32()
	s.TableName = decoder.ReadString255()
	n := int(decoder.ReadU8())

	for i := 0; i < n; i++ {
		s.Tags = append(s.Tags, Tag{decoder.ReadString255(), decoder.ReadString255()})
	}

	n = int(decoder.ReadU8())
	for i := 0; i < n; i++ {
		s.Fields = append(s.Fields, Field{decoder.ReadString255(), ValueType(decoder.ReadU8()), int64(decoder.ReadVarintU64())})
	}
	return s, nil
}

func (s *DFStats) WriteBlock(block *ckdb.Block) error {
	block.Write(s.Time)
	for _, tag := range s.Tags {
		block.Write(tag.Value)
	}
	for _, field := range s.Fields {
		if field.Type == TypeFloat64 {
			block.Write(*((*float64)(unsafe.Pointer(&field.Value))))
		} else {
			block.Write(field.Value)
		}
	}
	return nil
}

func (s *DFStats) OrgID() uint16 {
	return ckdb.DEFAULT_ORG_ID
}

func (s *DFStats) Release() {
	ReleaseDFStats(s)
}

func (s *DFStats) GenCKTable(ttl int) *ckdb.Table {
	timeKey := "time"
	var orderKeys []string
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumnWithGroupBy("time", ckdb.DateTime))
	for _, tag := range s.Tags {
		columns = append(columns, ckdb.NewColumnWithGroupBy(tag.Key, ckdb.LowCardinalityString))
		orderKeys = append(orderKeys, tag.Key)
	}
	for _, field := range s.Fields {
		if field.Type == TypeFloat64 {
			columns = append(columns, ckdb.NewColumn(field.Key, ckdb.Float64))
		} else {
			columns = append(columns, ckdb.NewColumn(field.Key, ckdb.Int64))
		}
	}

	orderKeys = append(orderKeys, timeKey)

	return &ckdb.Table{
		Version:         "20211122",
		Database:        DATABASE,
		LocalName:       s.TableName + "_local",
		GlobalName:      s.TableName,
		Columns:         columns,
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   ckdb.TimeFuncDay,
		Engine:          ckdb.MergeTree,
		Cluster:         ckdb.DF_CLUSTER,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

var poolDFStats = pool.NewLockFreePool(func() interface{} {
	return &DFStats{
		Tags:   make([]Tag, 0, 4),
		Fields: make([]Field, 0, 4),
	}
})

func AcquireDFStats() *DFStats {
	return poolDFStats.Get().(*DFStats)
}

func ReleaseDFStats(s *DFStats) {
	if s == nil {
		return
	}
	s.Time = 0
	s.TableName = ""
	s.Tags = s.Tags[:0]
	s.Fields = s.Fields[:0]

	poolDFStats.Put(s)
}
