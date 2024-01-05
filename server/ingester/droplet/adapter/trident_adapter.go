/*
 * Copyright (c) 2024 Yunshan Networks
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

package adapter

import (
	"io"
	"net"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	TRIDENT_TIMEOUT = 2 * time.Second

	BATCH_SIZE = 128

	TRIDENT_DISPATCHER_MAX = 16
)

var log = logging.MustGetLogger("trident_adapter")

type TridentKey = uint32

type packetBuffer struct {
	recvBuffer   *receiver.RecvBuffer
	buffer       []byte
	bufferLength int
	decoder      SequentialDecoder
	tridentIp    net.IP
	vtapId       uint16
	hash         uint8
}

type tridentDispatcher struct {
	cache        []*packetBuffer
	timestamp    []time.Duration // 对应cache[i]为nil时，值为后续最近一个包的timestamp，用于判断超时
	maxTimestamp time.Duration   // 历史接收包的最大时间戳，用于判断trident重启
	dropped      uint64
	seq          uint64 // cache中的第一个seq
	startIndex   uint64
}

type tridentInstance struct {
	// TCP连接创建的时候无法获取VtapId信息, 所以实例初始不会放在表中
	// 当接收到实例的第一个压缩报文获取到VtapId信息时, 才会加入到表中
	inTable     bool
	ip          net.IP
	dispatchers [TRIDENT_DISPATCHER_MAX]tridentDispatcher
}

type TridentAdapter struct {
	command
	io.Closer
	utils.Closable

	slaveCount uint8
	slaves     []*slave

	running bool
	decoder compressDecoder
}

func (p *packetBuffer) init() {
	p.decoder.initSequentialDecoder(p.buffer)
}

func (p *packetBuffer) calcHash(vtapId uint16) uint8 {
	hash := uint8(vtapId) ^ uint8(vtapId>>8) ^ uint8(p.decoder.tridentDispatcherIndex)
	p.hash = (hash >> 6) ^ (hash >> 4) ^ (hash >> 2) ^ hash
	p.vtapId = vtapId
	return p.hash
}

func minPowerOfTwo(v uint32) uint32 {
	for i := 0; i < 30; i++ {
		if v <= 1<<i {
			return 1 << i
		}
	}
	return 1 << 30
}

func NewTridentAdapter(in queue.QueueReader, queues []queue.QueueWriter, cacheSize uint32) *TridentAdapter {
	adapter := &TridentAdapter{
		slaveCount: uint8(len(queues)),
		slaves:     make([]*slave, len(queues)),
	}
	for i := uint8(0); i < adapter.slaveCount; i++ {
		adapter.slaves[i] = newSlave(int(i), queues[i])
	}
	adapter.command.init(adapter)
	adapter.decoder = newDecoder(in, uint64(cacheSize), adapter.slaves)
	common.RegisterCountableForIngester("trident-adapter", adapter)
	debug.Register(ingesterctl.INGESTERCTL_ADAPTER, adapter)
	return adapter
}

func (a *TridentAdapter) GetStatsCounter() interface{} {
	counter := &PacketCounter{}
	for i := uint8(0); i < a.slaveCount; i++ {
		slaveCounter := a.slaves[i].statsCounter.GetStatsCounter().(*PacketCounter)
		counter.add(slaveCounter)
	}
	counter.add(a.decoder.GetStatsCounter())
	return counter
}

func (a *TridentAdapter) GetInstances() []*tridentInstance {
	instances := make([]*tridentInstance, 0, 8)
	instances = append(instances, a.decoder.GetInstances()...)
	return instances
}

func (a *TridentAdapter) GetCounter() interface{} {
	counter := &PacketCounter{}
	for i := uint8(0); i < a.slaveCount; i++ {
		slaveCounter := a.slaves[i].statsCounter.GetCounter().(*PacketCounter)
		counter.add(slaveCounter)
	}
	counter.add(a.decoder.GetCounter())
	return counter
}

// io.Closer()
func (a *TridentAdapter) Close() error {
	a.running = false
	return nil
}

func cacheLookup(dispatcher *tridentDispatcher, packet *packetBuffer, cacheSize uint64, slaves []*slave) (uint64, uint64) {
	decoder := &packet.decoder
	seq := decoder.Seq()
	timestamp := decoder.timestamp

	// 初始化
	if dispatcher.seq == 0 {
		dispatcher.seq = seq
		log.Infof("receive first packet from trident %v index %d, with seq %d",
			packet.tridentIp, packet.decoder.tridentDispatcherIndex, dispatcher.seq)
	}
	dropped := uint64(0)

	// 倒退
	if seq < dispatcher.seq {
		if timestamp > dispatcher.maxTimestamp { // 序列号更小但时间更大，trident重启
			log.Warningf("trident %v index %d restart but some packets lost, received timestamp %d > %d, reset sequence to max(%d-%d, %d).",
				packet.tridentIp, packet.decoder.tridentDispatcherIndex,
				timestamp, dispatcher.maxTimestamp, seq, cacheSize, 1)
			// 重启前的包如果还在cache中一定存在丢失的部分，直接抛弃且不计数。
			for i := uint64(0); i < cacheSize; i++ {
				if dispatcher.cache[i] != nil {
					releasePacketBuffer(dispatcher.cache[i])
					dispatcher.cache[i] = nil
				}
				dispatcher.timestamp[i] = 0
			}
			// 重启时不记录丢包数，因为重启的影响更大，且已经触发了告警。
			if seq > cacheSize {
				dispatcher.seq = seq - cacheSize
			} else {
				dispatcher.seq = 1
			}
			dispatcher.startIndex = 0
		} else {
			// 乱序包，丢弃并返回。注意乱序一定意味着之前已经统计到了丢包。
			// 乱序接近丢弃说明是真乱序，乱序远比丢弃小说明是真丢包。
			log.Warningf("trident %v index %d hash seq %d less than current %d, drop packet",
				packet.tridentIp, packet.decoder.tridentDispatcherIndex, seq, dispatcher.seq)
			releasePacketBuffer(packet)
			return dropped, uint64(1)
		}
	}
	if timestamp > dispatcher.maxTimestamp {
		dispatcher.maxTimestamp = timestamp
	}

	// 尽量flush直至可cache
	offset := seq - dispatcher.seq
	for i := uint64(0); i < cacheSize && offset >= cacheSize; i++ {
		if dispatcher.cache[dispatcher.startIndex] != nil {
			p := dispatcher.cache[dispatcher.startIndex]
			slaves[p.hash&uint8(len(slaves)-1)].put(p)
			dispatcher.cache[dispatcher.startIndex] = nil
		} else {
			dropped++
		}
		dispatcher.timestamp[i] = 0
		dispatcher.seq++
		dispatcher.startIndex = (dispatcher.startIndex + 1) & (cacheSize - 1)
		offset--
	}
	if offset >= cacheSize {
		gap := offset - cacheSize + 1
		dispatcher.seq += gap
		dispatcher.startIndex = (dispatcher.startIndex + gap) & (cacheSize - 1)
		dropped += uint64(gap)
		offset -= gap
	}

	// 加入cache
	current := (dispatcher.startIndex + offset) & (cacheSize - 1)
	dispatcher.cache[current] = packet
	dispatcher.timestamp[current] = timestamp
	for i := current; i != dispatcher.startIndex; { // 设置尚未到达的包的最坏timestamp
		i = (i - 1) & (cacheSize - 1)
		if dispatcher.cache[i] != nil {
			break
		}
		dispatcher.timestamp[i] = timestamp
	}

	// 尽量flush直至有残缺、或超时
	for i := uint64(0); i < cacheSize; i++ {
		if dispatcher.cache[dispatcher.startIndex] != nil { // 可以flush
			p := dispatcher.cache[dispatcher.startIndex]
			slaves[p.hash&uint8(len(slaves)-1)].put(p)
			dispatcher.cache[dispatcher.startIndex] = nil
		} else if dispatcher.timestamp[dispatcher.startIndex] == 0 { // 没有更多packet
			break
		} else if timestamp-dispatcher.timestamp[dispatcher.startIndex] > TRIDENT_TIMEOUT { // 超时
			dropped++
		} else { // 无法移动窗口
			break
		}
		dispatcher.timestamp[dispatcher.startIndex] = 0

		dispatcher.seq++
		dispatcher.startIndex = (dispatcher.startIndex + 1) & (cacheSize - 1)
	}

	// 统计丢包数
	if dropped > 0 {
		dispatcher.dropped += dropped
		log.Debugf("trident %v index %d lost %d packets, packet received with seq %d, now window start with seq %d",
			packet.tridentIp, packet.decoder.tridentDispatcherIndex, dropped, seq, dispatcher.seq)
	}
	return dropped, uint64(0)
}

var packetBufferPool = pool.NewLockFreePool(
	func() interface{} {
		packet := new(packetBuffer)
		return packet
	},
	pool.OptionPoolSizePerCPU(16),
	pool.OptionInitFullPoolSize(16),
)

func acquirePacketBuffer(recvBuffer *receiver.RecvBuffer) *packetBuffer {
	p := packetBufferPool.Get().(*packetBuffer)
	p.recvBuffer = recvBuffer
	p.buffer = recvBuffer.Buffer[recvBuffer.Begin:recvBuffer.End]
	p.bufferLength = recvBuffer.End - recvBuffer.Begin
	p.tridentIp = recvBuffer.IP
	return p
}

func releasePacketBuffer(b *packetBuffer) {
	if b.recvBuffer != nil {
		receiver.ReleaseRecvBuffer(b.recvBuffer)
	}
	b.recvBuffer = nil
	b.buffer = nil
	b.bufferLength = 0
	b.tridentIp = nil
	packetBufferPool.Put(b)
}

func (a *TridentAdapter) startSlaves() {
	for i := uint8(0); i < a.slaveCount; i++ {
		go a.slaves[i].run()
	}
}

func (a *TridentAdapter) Start() error {
	if !a.running {
		log.Infof("Start trident adapter")
		a.running = true
		a.startSlaves()
		a.decoder.start()
	}
	return nil
}
