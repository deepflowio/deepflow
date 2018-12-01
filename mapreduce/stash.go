package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Stash struct {
	timestamp         uint32
	stashLocation     []map[string]int
	fastStashLocation []map[uint64]int
	slots             int

	stash      []interface{}
	entryCount int
	capacity   int

	encoder *codec.SimpleEncoder
}

func NewStash(capacity, slots int) *Stash {
	return &Stash{
		timestamp:         0,
		stashLocation:     make([]map[string]int, slots),
		fastStashLocation: make([]map[uint64]int, slots),
		slots:             slots,
		stash:             make([]interface{}, capacity),
		entryCount:        0,
		capacity:          capacity,
		encoder:           &codec.SimpleEncoder{},
	}
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
func (s *Stash) Add(docs []interface{}) []interface{} {
	for i, v := range docs {
		doc := v.(*app.Document)
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 || slot >= s.slots {
			return docs[i:]
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
				return docs[i:]
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
				return docs[i:]
			}
			s.stash[s.entryCount] = app.CloneDocument(doc)
			slotMap[doc.GetID(s.encoder)] = s.entryCount
			s.entryCount++
		}
	}
	return nil
}

func (s *Stash) Size() int {
	return s.entryCount
}

func (s *Stash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *Stash) Clear() {
	s.timestamp = 0
	s.stashLocation = make([]map[string]int, s.slots)
	s.fastStashLocation = make([]map[uint64]int, s.slots)
	s.entryCount = 0
}
