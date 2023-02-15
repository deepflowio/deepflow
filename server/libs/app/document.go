/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package app

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

const (
	VERSION                   = 20220117 // 修改Document的序列化结构时需同步修改此常量
	LAST_SIMPLE_CODEC_VERSION = 20220111 // 这个版本及之前的版本使用 simple_codec, 之后的版本使用pb_codec
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

func (d *Document) EncodePB(encoder *codec.SimpleEncoder, i interface{}) error {
	p, ok := i.(*pb.Document)
	if !ok {
		return fmt.Errorf("invalid interface type, should be *pb.Document")
	}
	if p.Meter == nil {
		p.Meter = &pb.Meter{}
	}
	flow := p.Meter.Flow
	app := p.Meter.App
	usage := p.Meter.Usage

	if err := d.WriteToPB(p); err != nil {
		return err
	}
	encoder.WritePB(p)
	if p.Meter.Flow == nil {
		p.Meter.Flow = flow
	}
	if p.Meter.App == nil {
		p.Meter.App = app
	}
	if p.Meter.Usage == nil {
		p.Meter.Usage = usage
	}
	return nil
}

func (d *Document) WriteToPB(p *pb.Document) error {
	p.Timestamp = d.Timestamp
	if p.Tag == nil {
		p.Tag = &pb.MiniTag{}
	}
	d.Tagger.(*zerodoc.MiniTag).WriteToPB(p.Tag)
	if p.Meter == nil {
		p.Meter = &pb.Meter{}
	}
	p.Meter.MeterId = uint32(d.Meter.ID())
	switch d.Meter.ID() {
	case zerodoc.FLOW_ID:
		if p.Meter.Flow == nil {
			p.Meter.Flow = &pb.FlowMeter{}
		}
		d.Meter.(*zerodoc.FlowMeter).WriteToPB(p.Meter.Flow)
		p.Meter.Usage, p.Meter.App = nil, nil
	case zerodoc.ACL_ID:
		if p.Meter.Usage == nil {
			p.Meter.Usage = &pb.UsageMeter{}
		}
		d.Meter.(*zerodoc.UsageMeter).WriteToPB(p.Meter.Usage)
		p.Meter.Flow, p.Meter.App = nil, nil
	case zerodoc.APP_ID:
		if p.Meter.App == nil {
			p.Meter.App = &pb.AppMeter{}
		}
		d.Meter.(*zerodoc.AppMeter).WriteToPB(p.Meter.App)
		p.Meter.Usage, p.Meter.Flow = nil, nil
	default:
		return errors.New(fmt.Sprintf("unknown meter id %d", d.Meter.ID()))
	}

	p.Flags = uint32(d.Flags)
	return nil
}

func (d *Document) WriteBlock(block *ckdb.Block) {
	d.Tagger.(*zerodoc.Tag).WriteBlock(block, d.Timestamp)
	d.Meter.WriteBlock(block)
}

func (d *Document) TableID() (uint8, error) {
	tag, _ := d.Tagger.(*zerodoc.Tag)
	return tag.TableID((d.Flags & FLAG_PER_SECOND_METRICS) == 1)
}
