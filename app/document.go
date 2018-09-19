package app

import (
	"fmt"
)

type Tag interface {
	GetID() string
	HasVariedField() bool
	ToKVString() string
	String() string
}

type Meter interface {
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToKVString() string
}

type Document struct {
	Timestamp uint32
	Tag
	Meter
}

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\n\ttag: %s\n\tmeter: %#v\n}\n", d.Timestamp, d.Tag.String(), d.Meter)
}
