package app

import "github.com/metaflowys/metaflow/server/libs/datatype"

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
