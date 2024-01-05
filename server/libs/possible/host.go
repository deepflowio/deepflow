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

package possible

import (
	"net"
	"sync"

	"github.com/deepflowio/deepflow/server/libs/hmap/lru"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type PossibleHost struct {
	hostMapMutex sync.RWMutex
	// key使用32bit的IP + 16bit的epc id + 1bit的v4 v6地址标记
	// 查询结果对于v4是准确的， 对于v6不一定准确
	hostMap *lru.U64LRU
}

func NewPossibleHost(capacity int) *PossibleHost {
	return &PossibleHost{hostMap: lru.NewU64LRU("possible-host", capacity/8, capacity)}
}

func (p *PossibleHost) Add(host uint32, epcId int32) {
	key := uint64(epcId&0xffff)<<32 | uint64(host)
	value := true
	p.hostMapMutex.Lock()
	p.hostMap.Add(key, &value)
	p.hostMapMutex.Unlock()
}

func (p *PossibleHost) Add6(host net.IP, epcId int32) {
	key := uint64(1<<48) | uint64(epcId&0xffff)<<32 | uint64(utils.GetIpHash(host))
	value := true
	p.hostMapMutex.Lock()
	p.hostMap.Add(key, &value)
	p.hostMapMutex.Unlock()
}

func (p *PossibleHost) Check(host uint32, epcId int32) bool {
	key := uint64(epcId&0xffff)<<32 | uint64(host)
	p.hostMapMutex.RLock()
	_, ok := p.hostMap.Get(key, true)
	p.hostMapMutex.RUnlock()
	return ok
}

func (p *PossibleHost) Check6(host net.IP, epcId int32) bool {
	key := uint64(1<<48) | uint64(epcId&0xffff)<<32 | uint64(utils.GetIpHash(host))
	p.hostMapMutex.RLock()
	_, ok := p.hostMap.Get(key, true)
	p.hostMapMutex.RUnlock()
	return ok
}

func (p *PossibleHost) Close() error {
	return p.hostMap.Close()
}
