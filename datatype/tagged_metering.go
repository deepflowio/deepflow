package datatype

import (
	"fmt"
)

type TaggedMetering struct {
	Metering
	Tag
}

func (m *TaggedMetering) PacketCount() uint64 {
	return m.PacketCount0 + m.PacketCount1
}

func (m *TaggedMetering) BitCount() uint64 {
	return (m.ByteCount0 + m.ByteCount1) << 3
}

func (t *TaggedMetering) String() string {
	return fmt.Sprintf("%s\n    Tag: %+v", &t.Metering, t.Tag)
}
