package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type Stash struct {
	timestamp         uint32
	stashLocation     []map[string]int
	fastStashLocation []map[uint64]map[uint64]int
	slots             int

	stash      []interface{}
	entryCount int
	capacity   int

	intBuffer *utils.IntBuffer
}

func NewStash(capacity, slots int) *Stash {
	return &Stash{
		timestamp:         0,
		stashLocation:     make([]map[string]int, slots),
		fastStashLocation: make([]map[uint64]map[uint64]int, slots),
		slots:             slots,
		stash:             make([]interface{}, capacity),
		entryCount:        0,
		capacity:          capacity,
		intBuffer:         &utils.IntBuffer{},
	}
}

// Add 添加到stash，会改变doc中meter的内容，若stash已满会返回未添加的doc
func (s *Stash) Add(docs []*app.Document) []*app.Document {
	for i, doc := range docs {
		if s.timestamp == 0 {
			s.timestamp = doc.Timestamp
		}
		slot := int(doc.Timestamp) - int(s.timestamp)
		if slot < 0 || slot >= s.slots {
			return docs[i:]
		}
		fastID := doc.GetFastID()
		code := doc.GetCode()
		if fastID != 0 {
			if s.fastStashLocation[slot] == nil {
				s.fastStashLocation[slot] = make(map[uint64]map[uint64]int)
			}
			if s.fastStashLocation[slot][code] == nil {
				s.fastStashLocation[slot][code] = make(map[uint64]int)
			}
			if docLoc, ok := s.fastStashLocation[slot][code][fastID]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				continue
			}
		} else {
			if s.stashLocation[slot] == nil {
				s.stashLocation[slot] = make(map[string]int)
			}
			if docLoc, ok := s.stashLocation[slot][doc.GetID(s.intBuffer)]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				continue
			}
		}

		if s.entryCount >= s.capacity {
			return docs[i:]
		}
		s.stash[s.entryCount] = doc
		if fastID != 0 {
			s.fastStashLocation[slot][code][fastID] = s.entryCount
		} else {
			s.stashLocation[slot][doc.GetID(s.intBuffer)] = s.entryCount
		}
		s.entryCount++
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
	s.fastStashLocation = make([]map[uint64]map[uint64]int, s.slots)
	s.entryCount = 0
}
