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
			slotMap := s.fastStashLocation[slot]
			if slotMap == nil {
				slotMap = make(map[uint64]map[uint64]int)
				s.fastStashLocation[slot] = slotMap
			}
			codeMap := slotMap[code]
			if codeMap == nil {
				codeMap = make(map[uint64]int)
				slotMap[code] = codeMap
			}
			if docLoc, ok := codeMap[fastID]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				if doc.Pool != nil {
					doc.Pool.Put(doc)
				}
				continue
			}

			if s.entryCount >= s.capacity {
				return docs[i:]
			}
			// 对于放入stash中的doc（即不是被merge的doc），需要复制其meter
			// 因为在app中不同的doc会共享同一个meter
			doc.Meter = doc.Meter.Duplicate()
			s.stash[s.entryCount] = doc
			codeMap[fastID] = s.entryCount
			s.entryCount++

		} else {
			slotMap := s.stashLocation[slot]
			if s.stashLocation[slot] == nil {
				slotMap = make(map[string]int)
				s.stashLocation[slot] = slotMap
			}
			if docLoc, ok := slotMap[doc.GetID(s.intBuffer)]; ok {
				s.stash[docLoc].(*app.Document).ConcurrentMerge(doc.Meter)
				if doc.Pool != nil {
					doc.Pool.Put(doc)
				}
				continue
			}

			if s.entryCount >= s.capacity {
				return docs[i:]
			}
			// 对于放入stash中的doc（即不是被merge的doc），需要复制其meter
			// 因为在app中不同的doc会共享同一个meter
			doc.Meter = doc.Meter.Duplicate()
			s.stash[s.entryCount] = doc
			slotMap[doc.GetID(s.intBuffer)] = s.entryCount
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
	s.fastStashLocation = make([]map[uint64]map[uint64]int, s.slots)
	s.entryCount = 0
}
