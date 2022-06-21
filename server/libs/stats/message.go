package stats

import (
	"errors"
	"unsafe"

	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
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
	if err := block.WriteUInt32(s.Time); err != nil {
		return err
	}
	for _, tag := range s.Tags {
		if err := block.WriteString(tag.Value); err != nil {
			return err
		}
	}
	for _, field := range s.Fields {
		if field.Type == TypeFloat64 {
			if err := block.WriteFloat64(*((*float64)(unsafe.Pointer(&field.Value)))); err != nil {
				return err
			}
		} else {
			if err := block.WriteInt64(field.Value); err != nil {
				return err
			}
		}
	}
	return nil
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
