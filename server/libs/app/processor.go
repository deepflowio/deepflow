package app

import "server/libs/datatype"

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
