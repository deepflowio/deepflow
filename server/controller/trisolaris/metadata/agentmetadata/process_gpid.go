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

package agentmetadata

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"google.golang.org/protobuf/proto"
)

type ProcessGPID struct {
	mu          sync.RWMutex
	version     atomic.Uint64
	entriesByte []byte
	md5         string
}

func NewProcessGPID() *ProcessGPID {
	p := &ProcessGPID{}
	p.version.Store(uint64(time.Now().Unix()) + uint64(rand.Intn(10000)))
	return p
}

func (p *ProcessGPID) Update(processes []*model.Process) error {
	entries := &agent.ProcessGPIDEntries{}
	for _, process := range processes {
		entries.Entries = append(entries.Entries, &agent.ProcessGPIDEntry{
			AgentId:    proto.Uint32(process.VTapID),
			GprocessId: proto.Uint32(process.GID),
			Pid:        proto.Uint32(uint32(process.PID)),
		})
	}
	entriesByte, err := entries.Marshal()
	if err != nil {
		return err
	}
	hash := md5.Sum(entriesByte)
	newMD5 := hex.EncodeToString(hash[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	if newMD5 == p.md5 {
		return nil
	}
	p.md5 = newMD5
	p.version.Add(1)
	p.entriesByte = entriesByte
	return nil
}

func (p *ProcessGPID) GetProcessGPIDByte(version uint64) (uint64, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	curVersion := p.version.Load()
	if version == curVersion {
		return version, []byte{}
	}
	return curVersion, p.entriesByte
}
