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

package adapter

import (
	"strconv"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

type slave struct {
	statsCounter

	inQueue   chan *packetBuffer
	outQueue  queue.QueueWriter
	block     *datatype.MetaPacketBlock
	itemBatch []interface{}
}

type slaveCounter struct {
	Size uint32 `statsd:"size,gauge"`
}

func (s *slave) prepareItem(count, index uint8) {
	if count > 0 {
		s.block.Count = count
		s.counter.TxPackets += uint64(count)
		s.stats.TxPackets += uint64(count)
		s.itemBatch = append(s.itemBatch, s.block)
		s.block = datatype.AcquireMetaPacketBlock()
	}
}

func (s *slave) decode(hash uint8, vtapId uint16, decoder *SequentialDecoder) {
	tapType, tapPort, index := decoder.tapType, decoder.tapPort, decoder.tridentDispatcherIndex

	i := uint8(0) // 使用a.block.Count, 因为i一定为0，直接赋值0
	for {
		meta := &s.block.Metas[i]
		meta.TapType = tapType
		meta.TapPort = tapPort
		meta.VtapId = vtapId
		meta.QueueHash = hash
		if decoder.NextPacket(meta) {
			s.prepareItem(i, index)
			break
		}
		i++
		if i >= datatype.META_PACKET_SIZE_PER_BLOCK {
			s.prepareItem(i, index)
			i = 0
		}
	}

	if len(s.itemBatch) > 0 {
		s.outQueue.Put(s.itemBatch...)
		s.itemBatch = s.itemBatch[:0]
	}
}

func (s *slave) put(packet *packetBuffer) {
	s.inQueue <- packet
}

func (s *slave) run() {
	for {
		packet := <-s.inQueue
		s.decode(packet.hash, packet.vtapId, &packet.decoder)
		releasePacketBuffer(packet)
	}
}

func (s *slave) GetCounter() interface{} {
	counter := &slaveCounter{}
	counter.Size = uint32(len(s.inQueue))
	return counter
}

func (s *slave) Closed() bool {
	return false // never close
}

func (s *slave) init(id int, out queue.QueueWriter) {
	s.block = datatype.AcquireMetaPacketBlock()
	s.outQueue = out
	s.inQueue = make(chan *packetBuffer, 1024)
	s.itemBatch = make([]interface{}, 0, QUEUE_BATCH_SIZE)
	s.statsCounter.init()
	common.RegisterCountableForIngester("slave-queue", s, stats.OptionStatTags{"index": strconv.Itoa(id)})
}

func newSlave(id int, out queue.QueueWriter) *slave {
	s := &slave{}
	s.init(id, out)
	return s
}
