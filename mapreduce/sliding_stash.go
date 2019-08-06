package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/app/common/tag"
)

type SlidingStash struct {
	timestamp     uint32
	stashLocation []*utils.U128ToU32Map
	slots         int
	marginSlots   int

	stash      []interface{}
	entryCount uint32
	capacity   uint32

	encoder *codec.SimpleEncoder
}

func NewSlidingStash(capacity uint32, slots, marginSlots int) Stash {
	stash := &SlidingStash{
		timestamp:     0,
		stashLocation: make([]*utils.U128ToU32Map, slots),
		slots:         slots,
		marginSlots:   marginSlots,
		stash:         make([]interface{}, capacity),
		entryCount:    0,
		capacity:      capacity,
		encoder:       &codec.SimpleEncoder{},
	}

	return stash
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
func (s *SlidingStash) Add(docs []interface{}) []interface{} {
	for i, v := range docs {
		doc := v.(*app.Document)
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp - uint32(s.marginSlots)
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 {
			// 当文档超出窗口的左边界时，下一个窗口的左边界以文档时间为准
			s.timestamp = doc.Timestamp - uint32(s.marginSlots)
			return docs[i:]
		} else if slot >= s.slots {
			// 当文档超出窗口的右边界时，下一个窗口的右边界以文档时间为准
			s.timestamp = doc.Timestamp + uint32(s.marginSlots) - uint32(s.slots) + 1
			return docs[i:]
		}

		slotMap := s.stashLocation[slot]
		if slotMap == nil {
			slotMap = utils.NewU128ToU32Map(s.capacity)
			s.stashLocation[slot] = slotMap
		}

		key0, key1 := tag.GetFastID(doc.Tag.(*zerodoc.Tag))
		loc, _ := slotMap.AddOrGet(key0, key1, s.entryCount, false)
		if loc < s.entryCount {
			s.stash[loc].(*app.Document).ConcurrentMerge(doc.Meter)
			continue
		}

		if loc >= s.capacity || slotMap.Width() > MAX_HASHMAP_WIDTH {
			return docs[i:]
		}
		s.stash[loc] = app.CloneDocument(doc)
		s.entryCount++
	}
	return nil
}

func (s *SlidingStash) Size() int {
	return int(s.entryCount)
}

func (s *SlidingStash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *SlidingStash) Clear() {
	for i := range s.stashLocation {
		if s.stashLocation[i] != nil {
			s.stashLocation[i].Clear()
		}
	}
	s.entryCount = 0
}

func (s *SlidingStash) GetWindowRight() uint32 {
	panic("do not use this")
}

func (s *SlidingStash) SetTimestamp(ts uint32) {
	panic("do not use this")
}
