package app

import "gitlab.x.lan/yunshan/droplet-libs/datatype"

type MeteringProcessor interface {
	GetName() string
	Process(*datatype.MetaPacket, bool) []*Document
}

type FlowProcessor interface {
	GetName() string
	Process(*datatype.TaggedFlow, bool) []*Document
}
