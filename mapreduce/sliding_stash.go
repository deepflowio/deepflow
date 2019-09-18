package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/hmap/idmap"
)

type SlidingStash struct {
	timestamp   uint32
	slots       int
	marginSlots int

	rawStash
}

func NewSlidingStash(capacity uint32, slots, marginSlots int) Stash {
	stash := &SlidingStash{
		timestamp:   0,
		slots:       slots,
		marginSlots: marginSlots,
		rawStash: rawStash{
			u128StashLocation: make([]*idmap.U128IDMap, slots),
			u320StashLocation: make([]*idmap.U320IDMap, slots),
			stash:             make([]interface{}, capacity),
			entryCount:        0,
			capacity:          capacity,
		},
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

		if !s.rawStash.Add(doc, slot) {
			return docs[i:]
		}
	}
	return nil
}

func (s *SlidingStash) GetWindowRight() uint32 {
	panic("do not use this")
}

func (s *SlidingStash) SetTimestamp(ts uint32) {
	panic("do not use this")
}
