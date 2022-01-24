package zerodoc

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
)

type Tagger interface {
	SetID(string)
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
