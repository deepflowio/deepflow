package docbuffer

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func NewMeterSharedDocBuffer() *utils.StructBuffer {
	b := &utils.StructBuffer{New: func() interface{} {
		doc := app.AcquireDocument() // 共享Meter，不要Release
		doc.Tag = (&outputtype.Field{}).NewTag(0)
		return doc
	}}

	// 初始化足够的空间，减少走Get分支
	for i := 0; i < 256; i++ {
		b.Get()
	}
	b.Reset()

	return b
}
