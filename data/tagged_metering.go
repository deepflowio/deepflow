package data

type TaggedMetering struct {
	Metering
	Tag
}

func (m *TaggedMetering) PktCnt() uint64 {
	return m.PktCnt0 + m.PktCnt1
}

func (m *TaggedMetering) BitCnt() uint64 {
	return (m.ByteCnt0 + m.ByteCnt1) << 3
}
