package app

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

type Tag interface {
	GetID(*codec.SimpleEncoder) string
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
	Encode(*codec.SimpleEncoder)
	Decode(*codec.SimpleDecoder)
	ConcurrentMerge(Meter)
	SequentialMerge(Meter)
	ToKVString() string
	SortKey() uint64
	Clone() Meter
	Release()
}

type Document struct {
	pool.ReferenceCount

	Timestamp uint32
	Tag
	Meter
	ActionFlags uint32
}

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\tActionFlags: b%b\n\ttag: %s\n\tmeter: %#v\n}\n",
		d.Timestamp, d.ActionFlags, d.Tag, d.Meter)
}

var poolDocument = pool.NewLockFreePool(func() interface{} {
	return &Document{}
})

func AcquireDocument() *Document {
	d := poolDocument.Get().(*Document)
	d.ReferenceCount.Reset()
	return d
}

func ReleaseDocument(doc *Document) {
	if doc == nil || doc.SubReferenceCount() {
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
