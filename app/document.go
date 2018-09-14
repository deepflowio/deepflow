package app

import (
	"fmt"
)

type Tag interface {
	GetID() string
	HasVariedField() bool
	ToMap() map[string]string
	String() string
}

type Meter interface {
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToMap() map[string]interface{}
}

type Document struct {
	Timestamp uint32
	Tag
	Meter
}

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\n\ttag: %s\n\tmeter: %#v\n}\n", d.Timestamp, d.Tag.String(), d.Meter)
}
