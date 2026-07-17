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
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
)

type ProcessGPID struct {
	mu              sync.RWMutex
	version         atomic.Uint64
	compressEntries []byte
	md5             string
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

	var compressEntries bytes.Buffer
	encoder, err := zstd.NewWriter(&compressEntries)
	if err != nil {
		return err
	}
	_, err = encoder.Write(entriesByte)
	if err != nil {
		return err
	}
	err = encoder.Close()
	if err != nil {
		return err
	}

	hash := md5.Sum(compressEntries.Bytes())
	newMD5 := hex.EncodeToString(hash[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	if newMD5 == p.md5 {
		return nil
	}
	p.md5 = newMD5
	p.version.Add(common.VERSION_OFFSET)
	p.compressEntries = compressEntries.Bytes()
	return nil
}

func (p *ProcessGPID) GetCompressProcessGPIDByte(version uint64) (uint64, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	curVersion := p.version.Load()
	if version == curVersion {
		return version, []byte{}
	}
	return curVersion, p.compressEntries
}
