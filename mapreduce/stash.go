package mapreduce

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type Stash struct {
	stashLocation map[uint32]map[string]int
	stash         []*app.Document
	entryCount    int
	capacity      int
}

func NewStash(capacity int) *Stash {
	return &Stash{
		make(map[uint32]map[string]int),
		make([]*app.Document, capacity),
		0,
		capacity,
	}
}

// Add 添加到stash，会改变doc中meter的内容
func (s *Stash) Add(docs ...*app.Document) bool {
	for _, doc := range docs {
		if docByTime, ok := s.stashLocation[doc.Timestamp]; ok {
			if docLoc, ok := docByTime[doc.GetID()]; ok {
				s.stash[docLoc].ConcurrentMerge(doc.Meter)
				continue
			}
		} else {
			s.stashLocation[doc.Timestamp] = make(map[string]int)
		}

		if s.entryCount >= s.capacity {
			return false
		}
		docByTime := s.stashLocation[doc.Timestamp]
		s.stash[s.entryCount] = doc
		docByTime[doc.GetID()] = s.entryCount
		s.entryCount++
	}
	return true
}

func (s *Stash) Size() int {
	return s.entryCount
}

// Full 返回true如果数量大于容量80%
func (s *Stash) Full() bool {
	return s.entryCount >= s.capacity*8/10
}

func (s *Stash) Dump() []*app.Document {
	return s.stash[:s.entryCount]
}

func (s *Stash) Clear() {
	s.stashLocation = make(map[uint32]map[string]int)
	s.entryCount = 0
}
