package zerodoc

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
)

type Tagger interface {
	GetID(*codec.SimpleEncoder) string
	SetID(string)
	Encode(*codec.SimpleEncoder)
	GetCode() uint64
	SetCode(uint64)
	GetTAPType() uint8
	ToKVString() string
	MarshalTo([]byte) int
	String() string
	Clone() Tagger
	Release()
}

type Meter interface {
	ID() uint8
	Name() string
	VTAPName() string
	Encode(*codec.SimpleEncoder)
	Decode(*codec.SimpleDecoder)
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToKVString() string
	MarshalTo([]byte) int
	SortKey() uint64
	Clone() Meter
	Release()
	Reverse()
	ToReversed() Meter
	WriteBlock(block *ckdb.Block) error // 写入clickhouse的block
}
