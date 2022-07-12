//go:build linux && xdp
// +build linux,xdp

/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package xdppacket

// 对外提供函数接口

import (
	"fmt"
	"net"
	"sync/atomic"

	. "github.com/google/gopacket"
)

type XDPMultiQueueStats struct {
	queueIds []int
	Stats    []XDPStats
}

type XDPMultiQueue struct {
	ifIndex      int
	options      *XDPOptions
	stats        *XDPStats    // 收发包统计(总量)
	xsks         []*XDPPacket // 每个队列对应一个XDPPacket
	batch        [][]byte     // 多队列收包buffer, 根据queueCount*batchSize申请, 按实际收包返回
	cis          []CaptureInfo
	socketIdx    []int
	progRefCount int32
}

func (m *XDPMultiQueue) initSockets() error {
	var combined *XDPSocket = nil
	loadProg := true

	for i, s := range m.xsks {
		if i == 0 {
			combined = s.XDPSocket
		} else {
			err := s.checkAndSetCombinedSocket(combined)
			if err != nil {
				m.Close()
				return err
			}
			loadProg = false
		}

		err := s.initXDPSocket(loadProg)
		if err != nil {
			m.Close()
			return err
		}

		atomic.AddInt32(&m.progRefCount, 1)
	}

	return m.xsks[0].setInterfaceRecvQueues()
}

// 创建支持多队列的xdp socket，返回各个队列对应的socket, 收发包使用单队列的API
func GetXDPSocketFromMultiQueue(multiQueue *XDPMultiQueue) []*XDPPacket {
	if multiQueue == nil || multiQueue.xsks == nil {
		return nil
	}
	return multiQueue.xsks
}

func NewXDPMultiQueue(name string, opts ...interface{}) (*XDPMultiQueue, error) {
	ifIndex, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("error Interface Name(%s) as %v", name, err)
	}

	options := &defaultOpt
	if len(opts) > 0 {
		options, err = parseOptions(opts...)
		if err != nil {
			return nil, err
		}
	}

	err = initXDPRunningEnv(name, options.xdpMode)
	if err != nil {
		return nil, err
	}

	m := &XDPMultiQueue{ifIndex: ifIndex.Index, options: options, stats: &XDPStats{}}
	queueCount := int(options.queueCount)
	batchCount := queueCount * int(options.batchSize)
	m.batch = make([][]byte, 0, batchCount)
	m.socketIdx = make([]int, 0, queueCount)
	m.cis = make([]CaptureInfo, 0, batchCount)

	xsks := make([]*XDPPacket, 0, queueCount)
	for i := 0; i < queueCount; i++ {
		s, err := initXDPPacket(ifIndex.Index, options, i)
		if err != nil {
			log.Errorf("create XDPSocket on queue %v failed as %v", i, err)
			m.Close()
			return nil, err
		}
		xsks = append(xsks, s)
		m.xsks = xsks
	}

	err = m.initSockets()
	if err != nil {
		m.Close()
		log.Errorf("init multi queue XDPSockets failed as %v", err)
		return nil, err
	}

	log.Debugf("multi queue XDPSockets: %v", m.xsks)
	return m, err
}

func (m *XDPMultiQueue) Close() {
	if m == nil {
		return
	}

	for _, s := range m.xsks {
		s.close()
		if atomic.LoadInt32(&m.progRefCount) > 0 {
			atomic.AddInt32(&m.progRefCount, -1)
		}

		// 清除ebpf program
		if atomic.LoadInt32(&m.progRefCount) == 0 {
			s.clearResource()
		}
	}
}

func (m *XDPMultiQueue) ZeroCopyReadPacket() ([][]byte, []CaptureInfo, error) {
	var err error
	var pkt []byte
	var ci CaptureInfo

	m.ReleaseReadPacket()
	for idx, s := range m.xsks {
		pkt, ci, err = s.ZeroCopyReadPacket()
		if err != nil {
			log.Debugf("queue %v ZeroCopyReadPacket failed as %v", s.queueId, err)
			break
		}
		m.batch = append(m.batch, pkt)
		m.cis = append(m.cis, ci)
		m.socketIdx = append(m.socketIdx, idx)
	}
	return m.batch, m.cis, err
}

func (m *XDPMultiQueue) ZeroCopyReadMultiPackets() ([][]byte, []CaptureInfo, error) {
	var err error
	var pkts [][]byte
	var cis []CaptureInfo

	m.ReleaseReadPacket()
	for idx, s := range m.xsks {
		pkts, cis, err = s.ZeroCopyReadMultiPackets()
		if err != nil {
			log.Debugf("queue %v ZeroCopyReadPacket failed as %v", s.queueId, err)
			break
		}
		m.batch = append(m.batch, pkts...)
		m.cis = append(m.cis, cis...)
		m.socketIdx = append(m.socketIdx, idx)
	}
	return m.batch, m.cis, err
}

func (m *XDPMultiQueue) ReleaseReadPacket() error {
	m.batch = m.batch[:0]
	m.socketIdx = m.socketIdx[:0]
	m.cis = m.cis[:0]
	return nil
}

func (m *XDPMultiQueue) ReadPacket() ([][]byte, []CaptureInfo, error) {
	_, cis, err := m.ZeroCopyReadPacket()
	if err != nil {
		return nil, nil, err
	}

	pktNum := len(m.batch)
	if pktNum == 0 {
		log.Debugf("no packet arrived")
		return nil, nil, nil
	}

	pkts := make([][]byte, pktNum)
	for i := 0; i < pktNum; i++ {
		pkts[i] = make([]byte, len(m.batch[i]))
		copy(pkts[i], m.batch[i])
	}

	return pkts, cis, nil
}

func (m *XDPMultiQueue) WritePacket(pkts [][]byte) (int, error) {
	var err error
	index := uint32(0)
	sendPkts := 0

	for _, pkt := range pkts {
		err = m.xsks[index].WritePacket(pkt)
		if err != nil {
			return sendPkts, err
		}
		sendPkts += 1
		index += 1
		index = index % m.options.queueCount
	}

	return sendPkts, nil
}

func (m *XDPMultiQueue) GetStats() XDPStats {
	tmpStats := XDPStats{}
	for i := 0; i < int(m.options.queueCount); i++ {
		tmpStats = tmpStats.Add(m.xsks[i].GetStats())
	}
	return tmpStats
}

func (m *XDPMultiQueue) GetStatsDetail() *XDPMultiQueueStats {
	queueCount := m.options.queueCount
	queues := make([]int, queueCount+1)
	stats := make([]XDPStats, queueCount+1)
	totalQueue := 0
	totalStats := XDPStats{}
	for i := 0; i < int(queueCount); i++ {
		queues[i+1] = m.xsks[i].queueId
		stats[i+1] = m.xsks[i].GetStats()
		totalQueue += 1
		totalStats = totalStats.Add(stats[i+1])
	}
	queues[0] = totalQueue
	stats[0] = totalStats

	return &XDPMultiQueueStats{
		queueIds: queues,
		Stats:    stats,
	}
}

func (x *XDPMultiQueue) ClearEbpfProg() {
	if x == nil {
		return
	}

	for _, s := range x.xsks {
		s.ClearEbpfProg()
	}
}
