package datatype

import (
	"fmt"
)

type TaggedFlow struct {
	Flow
	Tag
}

func (f *TaggedFlow) String() string {
	return fmt.Sprintf("Flow: %s, Tag: %+v", &f.Flow, f.Tag)
}
