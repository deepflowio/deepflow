// +build linux,xdp

package xdppacket

// 对外提供函数接口

import (
	"fmt"
	"net"
	"sync/atomic"

	. "github.com/google/gopacket"
	"github.com/pkg/errors"
)

type XDPMultiQueueStats struct {
	queueIds []int
	Stats    []*XDPStats
}

type XDPMultiQueue struct {
	queueCount   int
	xsks         []*XDPPacket // 每个队列对应一个XDPPacket
	batch        [][]byte     // 多队列收包buffer, 根据queueCount申请, 按实际收包返回
	cis          []CaptureInfo
	socketIdx    []int
	progRefCount int32
}

func (m *XDPMultiQueue) InitSockets() error {
	var combined *XDPSocket = nil
	loadProg := true

	queueCount := uint32(m.queueCount)
	for i, s := range m.xsks {
		if i == 0 {
			combined = s.XDPSocket
		} else { // i > 0
			err := s.checkAndSetCombinedSocket(combined)
			if err != nil {
				m.Close()
				return err
			}
			loadProg = false
		}

		err := s.initXDPSocket(loadProg, queueCount)
		if err != nil {
			m.Close()
			return err
		}

		atomic.AddInt32(&m.progRefCount, 1)
	}

	return nil
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

	if !initXDPRunningEnv(name, options.xdpMode, options.queueCount) {
		return nil, errors.New("an error XDP running environment")
	}

	m := &XDPMultiQueue{}
	m.queueCount = int(options.queueCount)
	m.batch = make([][]byte, 0, m.queueCount)
	m.socketIdx = make([]int, 0, m.queueCount)
	m.cis = make([]CaptureInfo, 0, m.queueCount)

	xsks := make([]*XDPPacket, 0, options.queueCount)
	for i := 0; i < m.queueCount; i++ {
		s, err := initXDPPacket(ifIndex.Index, options, i)
		if err != nil {
			log.Debugf("create XDPSocket on queue %v failed as %v", i, err)
			goto failed
		}
		xsks = append(xsks, s)
		m.xsks = xsks
	}

	m.InitSockets()
	log.Debugf("multi queue XDPSockets: %v", m.xsks)
	return m, nil

failed:
	m.Close()
	return nil, err
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
			continue
		}
		m.batch = append(m.batch, pkt)
		m.cis = append(m.cis, ci)
		m.socketIdx = append(m.socketIdx, idx)
	}
	return m.batch, m.cis, nil
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
	index := 0
	sendPkts := 0

	for _, pkt := range pkts {
		err = m.xsks[index].WritePacket(pkt)
		if err != nil {
			return sendPkts, err
		}
		sendPkts += 1
		index += 1
		index = index % m.queueCount
	}

	return sendPkts, nil
}

func (m *XDPMultiQueue) GetStats() *XDPMultiQueueStats {
	if m == nil {
		return nil
	}

	queues := make([]int, m.queueCount+1)
	stats := make([]*XDPStats, m.queueCount+1)
	totalQueue := 0
	totalStats := XDPStats{}
	for i := 0; i < int(m.queueCount); i++ {
		queues[i+1] = m.xsks[i].queueId
		stats[i+1] = m.xsks[i].GetStats()
		totalQueue += 1
		totalStats = *totalStats.Add(stats[i+1])
	}
	queues[0] = totalQueue
	stats[0] = &totalStats

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
