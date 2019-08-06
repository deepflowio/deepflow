package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/app/common/tag"
)

type FixedStash struct {
	timestamp     uint32
	stashLocation []*utils.U128ToU32Map
	slots         int

	stash      []interface{}
	entryCount uint32
	capacity   uint32

	encoder *codec.SimpleEncoder
}

func NewFixedStash(capacity uint32, slots int) Stash {
	stash := &FixedStash{
		timestamp:     0,
		stashLocation: make([]*utils.U128ToU32Map, slots),
		slots:         slots,
		stash:         make([]interface{}, capacity),
		entryCount:    0,
		capacity:      capacity,
		encoder:       &codec.SimpleEncoder{},
	}

	return stash
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
// 输入docs的timestamp一定是对齐到分钟的
func (s *FixedStash) Add(docs []interface{}) []interface{} {
	for i, v := range docs {
		doc := v.(*app.Document)
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp / MINUTE * MINUTE
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 {
			// 当文档超出窗口的左边界时，下一个窗口的左边界以文档时间所在分钟开始为准
			s.timestamp = doc.Timestamp / MINUTE * MINUTE
			return docs[i:]
		} else if slot >= s.slots {
			// 当文档超出窗口的右边界时，
			// 下一个窗口的左边界以文档时间减去安全区间（slots-1m）所在分钟开始为准
			// 这里要求slots的数量一定大于60
			s.timestamp = (doc.Timestamp - uint32(s.slots) + MINUTE) / MINUTE * MINUTE
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

func (s *FixedStash) Size() int {
	return int(s.entryCount)
}

func (s *FixedStash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *FixedStash) Clear() {
	for i := range s.stashLocation {
		if s.stashLocation[i] != nil {
			s.stashLocation[i].Clear()
		}
	}
	s.entryCount = 0
}

func (s *FixedStash) GetWindowRight() uint32 {
	return s.timestamp + uint32(s.slots)
}

func (s *FixedStash) SetTimestamp(ts uint32) {
	s.timestamp = ts
}
