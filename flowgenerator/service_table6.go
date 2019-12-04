package flowgenerator

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/hmap/lru"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

// 和IPv4算法相同

type ServiceTable6 struct {
	m *lru.U160LRU
}

const (
	_KEY_LEN = 20 // IP(16) + EPC(2) + PORT(2)
)

func ServiceKey6(key []byte, epcID int16, ip net.IP, port uint16) []byte {
	copy(key, ip)
	binary.BigEndian.PutUint16(key[16:], port)
	binary.BigEndian.PutUint16(key[18:], uint16(epcID))
	return key
}

func NewServiceTable6(tag string, index, hashSlots, capacity int) *ServiceTable6 {
	return &ServiceTable6{
		m: lru.NewU160LRU(fmt.Sprintf("flow_generator_service_table6_%s", tag), hashSlots, capacity, stats.OptionStatTags{"index": strconv.Itoa(index)}),
	}
}

func (t *ServiceTable6) getFirstPacketScore(srcKey, dstKey []byte) (uint8, uint8) {
	srcScore, dstScore := MIN_SCORE, MIN_SCORE
	if r, in := t.m.Get(srcKey, true); in {
		srcScore = r.(uint8)
	}
	if r, in := t.m.Get(dstKey, true); in {
		dstScore = r.(uint8)
	}

	if srcScore == MAX_SCORE || dstScore == MAX_SCORE { // 一旦有一侧发送过SYN|ACK，无需更新
		return srcScore, dstScore
	}

	if srcScore > MIN_SCORE {
		srcScore--
		if srcScore > MIN_SCORE {
			t.m.Add(srcKey, srcScore)
		} else {
			t.m.Remove(srcKey)
		}
	}

	if dstScore < MAX_SCORE-1 {
		dstScore++
		t.m.Add(dstKey, dstScore)
	}

	return srcScore, dstScore
}

func (t *ServiceTable6) GetTCPScore(isFirstPacket bool, tcpFlags uint8, srcKey, dstKey []byte) (uint8, uint8) {
	srcScore, dstScore := MIN_SCORE, MIN_SCORE

	if tcpFlags&TCP_FLAG_MASK == TCP_SYN|TCP_ACK { // 一旦发送SYN|ACK，即被认为是服务端，其对侧被认为不可能是服务端
		srcScore = MAX_SCORE
		t.m.Add(srcKey, srcScore)
		dstScore = MIN_SCORE
		t.m.Remove(dstKey)
	} else if tcpFlags&TCP_FLAG_MASK == TCP_SYN { // 一旦发送SYN，即被认为是客户端
		srcScore = MIN_SCORE
		t.m.Remove(srcKey)
		if r, in := t.m.Get(dstKey, true); in {
			dstScore = r.(uint8)
		}
		if isFirstPacket && dstScore < MAX_SCORE-1 {
			dstScore++
			t.m.Add(dstKey, dstScore)
		}
	} else if isFirstPacket {
		return t.getFirstPacketScore(srcKey, dstKey)
	} else {
		if r, in := t.m.Get(srcKey, true); in {
			srcScore = r.(uint8)
		}
		if r, in := t.m.Get(dstKey, true); in {
			dstScore = r.(uint8)
		}
	}

	return srcScore, dstScore
}

func (t *ServiceTable6) GetUDPScore(isFirstPacket bool, srcKey, dstKey []byte) (uint8, uint8) {
	srcScore, dstScore := MIN_SCORE, MIN_SCORE

	if isFirstPacket {
		return t.getFirstPacketScore(srcKey, dstKey)
	} else {
		if r, in := t.m.Get(srcKey, true); in {
			srcScore = r.(uint8)
		}
		if r, in := t.m.Get(dstKey, true); in {
			dstScore = r.(uint8)
		}
	}

	return srcScore, dstScore
}
