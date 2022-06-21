package app

import "gitlab.yunshan.net/yunshan/droplet-libs/datatype"

type MeteringProcessor interface {
	GetName() string
	Prepare()
	Process(*datatype.TaggedFlow, bool) []interface{}
}

type FlowProcessor interface {
	GetName() string
	Prepare()
	Process(*datatype.TaggedFlow, bool) []interface{}
}
