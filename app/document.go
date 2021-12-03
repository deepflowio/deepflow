package app

import (
	"errors"
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
)

const (
	VERSION = 20211209 // 修改Document的序列化结构时需同步修改此常量
)

type DocumentFlag uint32

type Document struct {
	pool.ReferenceCount

	Timestamp uint32
	zerodoc.Tagger
	zerodoc.Meter
	Flags DocumentFlag
}

const (
	FLAG_PER_SECOND_METRICS DocumentFlag = 1 << iota
)

func (d Document) String() string {
	return fmt.Sprintf("\n{\n\ttimestamp: %d\tFlags: b%b\n\ttag: %s\n\tmeter: %#v\n}\n",
		d.Timestamp, d.Flags, d.Tagger, d.Meter)
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

	if doc.Tagger != nil {
		doc.Tagger.Release()
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
	newDoc.Tagger = doc.Tagger.Clone()
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
	if d.Tagger == nil || d.Meter == nil {
		return errors.New("No tag or meter in document")
	}
	encoder.WriteU32(d.Timestamp)
	d.Tagger.Encode(encoder)
	encoder.WriteU8(d.Meter.ID())
	d.Meter.Encode(encoder)
	encoder.WriteU32(uint32(d.Flags))
	return nil
}
