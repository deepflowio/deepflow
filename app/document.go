package app

import (
	"fmt"
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type Tag interface {
	GetID(*utils.IntBuffer) string
	SetID(string)
	GetCode() uint64
	GetFastID() uint64
	HasVariedField() bool
	ToKVString() string
	String() string
	Clone() Tag
	Release()
}

type Meter interface {
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToKVString() string
	Clone() Meter
	Release()
}

type Document struct {
	Timestamp uint32
	Tag
	Meter
	ActionFlags uint32
}

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\tActionFlags: b%b\n\ttag: %s\n\tmeter: %#v\n}\n",
		d.Timestamp, d.ActionFlags, d.Tag, d.Meter)
}

var poolDocument sync.Pool = sync.Pool{
	New: func() interface{} {
		return &Document{}
	},
}

func AcquireDocument() *Document {
	ReleaseDocument(&Document{})
	return poolDocument.Get().(*Document)
}

func ReleaseDocument(doc *Document) {
	if doc == nil {
		return
	}
	if doc.Tag != nil {
		doc.Tag.Release()
	}
	if doc.Meter != nil {
		doc.Meter.Release()
	}
	*doc = Document{}
	poolDocument.Put(doc)
}

func CloneDocument(doc *Document) *Document {
	newDoc := AcquireDocument()
	newDoc.Timestamp = doc.Timestamp
	newDoc.Tag = doc.Tag.Clone()
	newDoc.Meter = doc.Meter.Clone()
	newDoc.ActionFlags = doc.ActionFlags
	return newDoc
}
