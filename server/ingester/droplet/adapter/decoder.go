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
	"math"
	"net"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

const (
	QUEUE_BATCH_SIZE = 1024
)

type compressDecoder interface {
	start()
	GetStatsCounter() *PacketCounter
	GetCounter() *PacketCounter
	GetInstances() []*tridentInstance
}

type decoder struct {
	in queue.QueueReader
	statsCounter
	slaves []*slave

	cacheSize uint64

	instancesLock sync.Mutex // 仅用于droplet-ctl打印trident信息
	instances     [math.MaxUint16 + 1]*tridentInstance
}

func (r *decoder) GetStatsCounter() *PacketCounter {
	counter, _ := r.statsCounter.GetStatsCounter().(*PacketCounter)
	return counter
}

func (r *decoder) GetCounter() *PacketCounter {
	counter, _ := r.statsCounter.GetCounter().(*PacketCounter)
	return counter
}

func (r *decoder) GetInstances() []*tridentInstance {
	instances := make([]*tridentInstance, 0, 8)
	r.instancesLock.Lock()
	for _, instance := range r.instances {
		if instance != nil {
			instances = append(instances, instance)
		}
	}
	r.instancesLock.Unlock()
	return instances
}

func (r *decoder) init(cacheSize uint64, slaves []*slave) {
	r.slaves = slaves
	r.cacheSize = cacheSize
}

func (r *decoder) deleteInstance(ip net.IP) {
	r.instancesLock.Lock()
	for i := 0; i < math.MaxUint16; i++ {
		if r.instances[i] != nil && r.instances[i].ip.Equal(ip) {
			r.instances[i] = nil
		}
	}
	r.instancesLock.Unlock()
}

func (r *decoder) addInstance(vtapId uint16, instance *tridentInstance) {
	instance.inTable = true
	r.instancesLock.Lock()
	r.instances[vtapId] = instance
	r.instancesLock.Unlock()
}

func (r *decoder) cacheInstance(instance *tridentInstance, packet *packetBuffer) {
	index := packet.decoder.tridentDispatcherIndex
	dispatcher := &instance.dispatchers[index]
	if dispatcher.cache == nil {
		dispatcher.cache = make([]*packetBuffer, r.cacheSize)
		dispatcher.timestamp = make([]time.Duration, r.cacheSize)
	}
	if !instance.inTable {
		r.addInstance(packet.vtapId, instance)
	}

	rxDropped, rxErrors := cacheLookup(dispatcher, packet, r.cacheSize, r.slaves)
	r.counter.RxPackets++
	r.counter.RxDropped += rxDropped
	r.counter.RxErrors += rxErrors
	r.stats.RxPackets++
	r.stats.RxDropped += rxDropped
	r.stats.RxErrors += rxErrors
}

func (r *decoder) findAndAdd(packet *packetBuffer) {
	instance := r.instances[packet.vtapId]
	if instance == nil {
		instance = &tridentInstance{inTable: true}
		instance.ip = packet.tridentIp
		r.instancesLock.Lock()
		r.instances[packet.vtapId] = instance
		r.instancesLock.Unlock()
	}
	r.cacheInstance(instance, packet)
}

func newDecoder(in queue.QueueReader, cacheSize uint64, slaves []*slave) compressDecoder {
	decoder := &decoder{}

	decoder.in = in
	decoder.statsCounter.init()
	decoder.init(cacheSize, slaves)
	return decoder
}

func (r *decoder) decodeCompress(packet *packetBuffer) {
	packet.init()
	invalid, vtapId := packet.decoder.DecodeHeader(uint16(packet.bufferLength))
	if invalid {
		r.counter.RxInvalid++
		r.stats.RxInvalid++
		releasePacketBuffer(packet)
		return
	}
	packet.calcHash(vtapId)
	r.findAndAdd(packet)
}

func (r *decoder) start() {
	go r.run()
}

func (r *decoder) run() {
	items := make([]interface{}, QUEUE_BATCH_SIZE)
	for {
		n := r.in.Gets(items)
		for i := 0; i < n; i++ {
			item := items[i]
			if recvBuffer, ok := item.(*receiver.RecvBuffer); ok {
				r.decodeCompress(acquirePacketBuffer(recvBuffer))
			} else if item == nil { // flush ticker
			} else {
				log.Warning("get queue data type wrong")
			}
		}
	}
}
