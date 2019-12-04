package mapreduce

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/hmap/idmap"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/app/common/tag"
)

type Stash interface {
	SetIndex(tag string, index int)
	Add(docs []interface{}) []interface{}
	Size() int
	Dump() []interface{}
	Clear()
	GetWindowRight() uint32
	SetTimestamp(ts uint32)
}

type rawStash struct {
	tag   string
	index int

	u128StashLocation []*idmap.U128IDMap
	u320StashLocation []*idmap.U320IDMap

	stash      []interface{}
	entryCount uint32
	capacity   uint32
}

func (s *rawStash) SetIndex(tag string, index int) {
	s.tag = tag
	s.index = index
}

// Add 添加到stash，会改变doc中meter的内容，成功返回true，否则返回false
func (s *rawStash) Add(doc *app.Document, slot int) bool {
	var loc uint32
	var width int
	zTag := doc.Tag.(*zerodoc.Tag)
	if zTag.IsIPv6 != 0 {
		if s.u320StashLocation[slot] == nil {
			s.u320StashLocation[slot] = idmap.NewU320IDMap(
				fmt.Sprintf("mapreduce_u320_stash_location_%s", s.tag),
				s.capacity,
				stats.OptionStatTags{"index": strconv.Itoa(s.index)},
			)
		}
		slotMap := s.u320StashLocation[slot]
		var keys [U320_KEY_LEN]byte
		tag.GetFastID(zTag, keys[:])
		var hash uint32
		for i := 0; i < U320_KEY_LEN; i += 4 {
			hash ^= binary.BigEndian.Uint32(keys[i:])
		}
		loc, _ = slotMap.AddOrGet(keys[:], hash, s.entryCount, false)
		width = slotMap.Width()
	} else {
		if s.u128StashLocation[slot] == nil {
			s.u128StashLocation[slot] = idmap.NewU128IDMap(
				fmt.Sprintf("mapreduce_u128_stash_location_%s", s.tag),
				s.capacity,
				stats.OptionStatTags{"index": strconv.Itoa(s.index)},
			)
		}
		slotMap := s.u128StashLocation[slot]
		var keys [U128_KEY_LEN]byte
		tag.GetFastID(zTag, keys[:])
		key0, key1 := binary.BigEndian.Uint64(keys[:]), binary.BigEndian.Uint64(keys[U128_KEY_LEN/2:])
		loc, _ = slotMap.AddOrGet(key0, key1, s.entryCount, false)
		width = slotMap.Width()
	}

	if loc < s.entryCount {
		s.stash[loc].(*app.Document).ConcurrentMerge(doc.Meter)
		return true
	}

	if loc >= s.capacity || width > MAX_HASHMAP_WIDTH {
		return false
	}
	s.stash[loc] = app.CloneDocument(doc)
	s.entryCount++
	return true
}

func (s *rawStash) Size() int {
	return int(s.entryCount)
}

func (s *rawStash) Dump() []interface{} {
	return s.stash[:s.entryCount]
}

func (s *rawStash) Clear() {
	for i := range s.u128StashLocation {
		if s.u128StashLocation[i] != nil {
			s.u128StashLocation[i].Clear()
		}
	}
	for i := range s.u320StashLocation {
		if s.u320StashLocation[i] != nil {
			s.u320StashLocation[i].Clear()
		}
	}
	s.entryCount = 0
}
