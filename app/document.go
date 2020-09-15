package app

import (
	"errors"
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

const (
	VERSION               = 20200915 // 修改Document的序列化结构时需同步修改此常量
	MAX_DOC_STRING_LENGTH = 1024
)

type Tag interface {
	GetID(*codec.SimpleEncoder) string
	SetID(string)
	Encode(*codec.SimpleEncoder)
	GetCode() uint64
	GetTAPType() uint8
	ToKVString() string
	MarshalTo([]byte) int
	String() string
	Clone() Tag
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
}

type DocumentFlag uint32

type Document struct {
	pool.ReferenceCount

	Timestamp uint32
	Tag
	Meter
	Flags DocumentFlag
}

const (
	FLAG_PER_SECOND_METRICS DocumentFlag = 1 << iota
)

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\tFlags: b%b\n\ttag: %s\n\tmeter: %#v\n}\n",
		d.Timestamp, d.Flags, d.Tag, d.Meter)
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
	newDoc.Flags = doc.Flags
	return newDoc
}

func PseudoCloneDocument(doc *Document) {
	doc.AddReferenceCount()
}

func (d *Document) Release() {
	ReleaseDocument(d)
}

func (d *Document) Encode(encoder *codec.SimpleEncoder) error {
	if d.Tag == nil || d.Meter == nil {
		return errors.New("No tag or meter in document")
	}
	encoder.WriteU32(d.Timestamp)
	d.Tag.Encode(encoder)
	encoder.WriteU8(d.Meter.ID())
	d.Meter.Encode(encoder)
	encoder.WriteU32(uint32(d.Flags))
	return nil
}
