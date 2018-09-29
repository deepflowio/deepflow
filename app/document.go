package app

import (
	"fmt"
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type Tag interface {
	GetID(*utils.IntBuffer) string
	GetCode() uint64
	GetFastID() uint64
	HasVariedField() bool
	ToKVString() string
	String() string
}

type Meter interface {
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToKVString() string
	Duplicate() Meter
}

type Document struct {
	Timestamp uint32
	Tag
	Meter
	Actions uint32
	Pool    *sync.Pool
}

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\n\ttag: %s\n\tmeter: %#v\n}\n", d.Timestamp, d.Tag.String(), d.Meter)
}
