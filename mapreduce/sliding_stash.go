package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

type SlidingStash struct {
	timestamp         uint32
	stashLocation     []map[string]int
	fastStashLocation [][]map[uint64]int
	slots             int
	marginSlots       int

	stash          []interface{}
	entryCount     int
	capacity       int
	variedDocLimit int

	encoder *codec.SimpleEncoder
}

const TAP_TYPE_COUNT = 32

func NewSlidingStash(capacity, variedDocLimit, slots, marginSlots int) Stash {
	stash := &SlidingStash{
		timestamp:         0,
		stashLocation:     make([]map[string]int, slots),
		fastStashLocation: make([][]map[uint64]int, TAP_TYPE_COUNT),
		slots:             slots,
		marginSlots:       marginSlots,
		stash:             make([]interface{}, capacity),
		entryCount:        0,
		capacity:          capacity,
		variedDocLimit:    variedDocLimit,
		encoder:           &codec.SimpleEncoder{},
	}

	for i := 0; i < TAP_TYPE_COUNT; i++ {
		stash.fastStashLocation[i] = make([]map[uint64]int, slots)
	}

	return stash
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
func (s *SlidingStash) Add(docs []interface{}) ([]interface{}, uint64) {
	rejected := uint64(0)
	for i, v := range docs {
		doc := v.(*app.Document)
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp - uint32(s.marginSlots)
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 {
			// 当文档超出窗口的左边界时，下一个窗口的左边界以文档时间为准
			s.timestamp = doc.Timestamp - uint32(s.marginSlots)
			return docs[i:], rejected
		} else if slot >= s.slots {
			// 当文档超出窗口的右边界时，下一个窗口的右边界以文档时间为准
			s.timestamp = doc.Timestamp + uint32(s.marginSlots) - uint32(s.slots) + 1
			return docs[i:], rejected
		}

		fastID := doc.GetFastID()
		tapType := doc.GetTAPType()
		if fastID != 0 {
			slotMap := s.fastStashLocation[tapType][slot]
			if slotMap == nil {
				slotMap = make(map[uint64]int)
				s.fastStashLocation[tapType][slot] = slotMap
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

func (s *SlidingStash) Size() int {
	return s.entryCount
}

func (s *SlidingStash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *SlidingStash) Clear() {
	s.stashLocation = make([]map[string]int, s.slots)
	for i := 0; i < TAP_TYPE_COUNT; i++ {
		s.fastStashLocation[i] = make([]map[uint64]int, s.slots)
	}
	s.entryCount = 0
}

func (s *SlidingStash) GetWindowRight() uint32 {
	panic("do not use this")
}

func (s *SlidingStash) SetTimestamp(ts uint32) {
	panic("do not use this")
}
