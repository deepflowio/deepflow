package flowgenerator

import (
	"gitlab.x.lan/yunshan/droplet-libs/hmap/lru"
)

// 对于TCP流量：
//   当发送SYN|ACK时，认为一定是服务端（MAX_SCORE），且此时对端一定是客户端（MIN_SCORE）。
//   当发送SYN时，认为一定是客户端（MIN_SCORE），但此时对端不一定是服务端，因为可能存在端口扫描。
// 对于TCP和UDP流量：
//   对于首包，每出现一次在目的端将score+1，每出现一次在源端将score-1。
//   但SYN|ACK的判断是最高优先级，上述score的调整不会对发送SYN|ACK的服务生效。
// 对于TCP/UDP：
//   IsClientToServer的判断方法为score大的一侧认为是服务端。
//   IsActiveService的判断方法为目的端=MAX_SCORE，即当前只认为发送过SYN|ACK的TCP服务为活跃服务。

const (
	MAX_SCORE = uint8(0xFF)
	MIN_SCORE = uint8(0)
)

type ServiceTable struct {
	m *lru.U64LRU
}

func ServiceKey(epcID int16, ipHash uint32, port uint16) uint64 {
	return (uint64(ipHash) << 32) | (uint64(port) << 16) | (uint64(epcID) & 0xFFFF)
}

func IsClientToServer(srcScore, dstScore uint8) bool {
	return srcScore <= dstScore // 分数相等也认为是C2S，避免reverseFlow
}

func IsActiveService(srcScore, dstScore uint8) bool {
	return dstScore == MAX_SCORE
}

func NewServiceTable(hashSlots, capacity int) *ServiceTable {
	return &ServiceTable{m: lru.NewU64LRU(hashSlots, capacity)}
}

func (t *ServiceTable) getFirstPacketScore(srcKey, dstKey uint64) (uint8, uint8) {
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

func (t *ServiceTable) GetTCPScore(isFirstPacket bool, tcpFlags uint8, srcKey, dstKey uint64) (uint8, uint8) {
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

func (t *ServiceTable) GetUDPScore(isFirstPacket bool, srcKey, dstKey uint64) (uint8, uint8) {
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
