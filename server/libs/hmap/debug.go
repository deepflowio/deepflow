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

package hmap

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/op/go-logging"
)

const (
	DEFAULT_DEBUG_INTERVAL = time.Second
)

var log = logging.MustGetLogger("hmap")

type Debug interface {
	ID() string
	KeySize() int
	GetCollisionChain() []byte
	SetCollisionChainDebugThreshold(int)
}

func dumpHexBytes(bs []byte) string {
	sb := strings.Builder{}
	sb.WriteString("0x")
	isZero := true
	for _, b := range bs {
		if isZero {
			if b == 0 {
				continue
			} else {
				isZero = false
				sb.WriteString(fmt.Sprintf("%x", b))
			}
		} else {
			sb.WriteString(fmt.Sprintf("%02x", b))
		}
	}
	if isZero {
		sb.WriteRune('0')
	}
	return sb.String()
}

func DumpHexBytesGrouped(bs []byte, size int) string {
	if len(bs) == 0 {
		return ""
	}
	nKeys := len(bs) / size
	keys := make([]string, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		if i < nKeys-1 {
			keys = append(keys, dumpHexBytes(bs[i*size:(i+1)*size]))
		} else {
			keys = append(keys, dumpHexBytes(bs[i*size:]))
		}
	}
	return strings.Join(keys, "-")
}

func DumpCollisionChain(d Debug) string {
	return DumpHexBytesGrouped(d.GetCollisionChain(), d.KeySize())
}

var hmapDebugger = Debugger{interval: DEFAULT_DEBUG_INTERVAL}

func RegisterForDebug(ds ...Debug) {
	hmapDebugger.Register(ds...)
}

func DeregisterForDebug(ds ...Debug) {
	hmapDebugger.Deregister(ds...)
}

func SetCollisionChainDebugThreshold(t int) {
	hmapDebugger.SetCollisionChainDebugThreshold(t)
}

type Debugger struct {
	exit      uint32
	interrupt chan struct{}
	interval  time.Duration
	isRunning bool

	collisionChainDebugThreshold int

	items []Debug
	m     sync.Mutex
}

func (d *Debugger) process() {
	d.m.Lock()
	items := make([]Debug, len(d.items))
	copy(items, d.items)
	d.m.Unlock()
	for _, it := range items {
		if chain := DumpCollisionChain(it); chain != "" {
			log.Debugf("hmap long chain type=%T id=%s chain=%s", it, it.ID(), chain)
		}
	}
}

func (d *Debugger) run() {
	for atomic.LoadUint32(&d.exit) == 0 {
		ticker := time.NewTicker(d.interval)
	INNER:
		for {
			select {
			case <-d.interrupt:
				break INNER
			case <-ticker.C:
				d.process()
			}
		}
		ticker.Stop()
	}
}

func (d *Debugger) SetCollisionChainDebugThreshold(t int) {
	if d.collisionChainDebugThreshold == t {
		return
	}
	d.collisionChainDebugThreshold = t
	d.m.Lock()
	for _, it := range d.items {
		it.SetCollisionChainDebugThreshold(t)
	}
	d.m.Unlock()
	if t > 0 {
		d.Start()
	} else {
		d.Stop()
	}
}

func (d *Debugger) SetInterval(interval time.Duration) {
	d.interval = interval
	d.interrupt <- struct{}{}
}

func (d *Debugger) Register(ds ...Debug) {
	for _, it := range ds {
		it.SetCollisionChainDebugThreshold(d.collisionChainDebugThreshold)
	}
	d.m.Lock()
	d.items = append(d.items, ds...)
	d.m.Unlock()
}

func (d *Debugger) Deregister(ds ...Debug) {
	d.m.Lock()
	for _, it := range ds {
		index := -1
		for i, item := range d.items {
			if item == it {
				index = i
				break
			}
		}
		if index == -1 {
			continue
		}
		length := len(d.items)
		if index < length-1 {
			copy(d.items[index:], d.items[index+1:])
		}
		d.items = d.items[:length-1]
	}
	d.m.Unlock()
}

func (d *Debugger) Start() error {
	if d.isRunning {
		return nil
	}
	d.exit = 0
	d.interrupt = make(chan struct{})
	d.isRunning = true
	go d.run()
	return nil
}

func (d *Debugger) Stop() error {
	if !d.isRunning {
		return nil
	}
	atomic.StoreUint32(&d.exit, 1)
	d.interrupt <- struct{}{}
	d.isRunning = false
	return nil
}
