package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

type FixedStash struct {
	timestamp         uint32
	stashLocation     []map[string]int
	fastStashLocation []map[uint64]int
	slots             int

	stash          []interface{}
	entryCount     int
	capacity       int
	variedDocLimit int

	encoder *codec.SimpleEncoder
}

func NewFixedStash(capacity, variedDocLimit, slots int) Stash {
	return &FixedStash{
		timestamp:         0,
		stashLocation:     make([]map[string]int, slots),
		fastStashLocation: make([]map[uint64]int, slots),
		slots:             slots,
		stash:             make([]interface{}, capacity),
		entryCount:        0,
		capacity:          capacity,
		variedDocLimit:    variedDocLimit,
		encoder:           &codec.SimpleEncoder{},
	}
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
// 输入docs的timestamp一定是对齐到分钟的
func (s *FixedStash) Add(docs []interface{}) ([]interface{}, uint64) {
	rejected := uint64(0)
	for i, v := range docs {
		doc := v.(*app.Document)
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp / MINUTE * MINUTE
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 {
			// 当文档超出窗口的左边界时，下一个窗口的左边界以文档时间所在分钟开始为准
			s.timestamp = doc.Timestamp / MINUTE * MINUTE
			return docs[i:], rejected
		} else if slot >= s.slots {
			// 当文档超出窗口的右边界时，
			// 下一个窗口的左边界以文档时间减去安全区间（slots-1m）所在分钟开始为准
			// 这里要求slots的数量一定大于60
			s.timestamp = (doc.Timestamp - uint32(s.slots) + MINUTE) / MINUTE * MINUTE
			return docs[i:], rejected
		}

		fastID := doc.GetFastID()
		if fastID != 0 {
			slotMap := s.fastStashLocation[slot]
			if slotMap == nil {
				slotMap = make(map[uint64]int)
				s.fastStashLocation[slot] = slotMap
			}
			if docLoc, ok := slotMap[fastID]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				continue
			}
			if s.entryCount >= s.capacity {
				return docs[i:], rejected
			}
			if doc.Tag.(*zerodoc.Tag).HasVariedField() && s.entryCount >= s.variedDocLimit {
				rejected++
				continue
			}

			s.stash[s.entryCount] = app.CloneDocument(doc)
			slotMap[fastID] = s.entryCount
			s.entryCount++

		} else {
			slotMap := s.stashLocation[slot]
			if s.stashLocation[slot] == nil {
				slotMap = make(map[string]int)
				s.stashLocation[slot] = slotMap
			}
			if docLoc, ok := slotMap[doc.GetID(s.encoder)]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				continue
			}
			if s.entryCount >= s.capacity {
				return docs[i:], rejected
			}
			if doc.Tag.(*zerodoc.Tag).HasVariedField() && s.entryCount >= s.variedDocLimit {
				rejected++
				continue
			}

			s.stash[s.entryCount] = app.CloneDocument(doc)
			slotMap[doc.GetID(s.encoder)] = s.entryCount
			s.entryCount++
		}
	}
	return nil, rejected
}

func (s *FixedStash) Size() int {
	return s.entryCount
}

func (s *FixedStash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *FixedStash) Clear() {
	s.stashLocation = make([]map[string]int, s.slots)
	s.fastStashLocation = make([]map[uint64]int, s.slots)
	s.entryCount = 0
}

func (s *FixedStash) GetWindowRight() uint32 {
	return s.timestamp + uint32(s.slots)
}

func (s *FixedStash) SetTimestamp(ts uint32) {
	s.timestamp = ts
}
