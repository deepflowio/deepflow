/**
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

package cache

import (
	"sync"
	"sync/atomic"

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelName struct {
	org    *common.ORG
	active atomic.Value // map[string]int

	mu              sync.RWMutex
	pendingNameToID map[string]int
}

func newLabelName(org *common.ORG) *labelName {
	ln := &labelName{
		org:             org,
		pendingNameToID: make(map[string]int),
	}
	ln.active.Store(make(map[string]int))
	return ln
}

func (ln *labelName) getActive() map[string]int {
	if active := ln.active.Load(); active != nil {
		return active.(map[string]int)
	}
	return map[string]int{}
}

func (ln *labelName) replaceActive(newActive map[string]int) {
	ln.active.Store(newActive)
}

func (ln *labelName) GetIDByName(n string) (int, bool) {
	if id, ok := ln.getActive()[n]; ok {
		return id, true
	}
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	id, ok := ln.pendingNameToID[n]
	return id, ok
}

func (ln *labelName) GetNameToID() map[string]int {
	active := ln.getActive()
	ln.mu.RLock()
	snapshot := make(map[string]int, len(active)+len(ln.pendingNameToID))
	for k, v := range active {
		snapshot[k] = v
	}
	for k, v := range ln.pendingNameToID {
		snapshot[k] = v
	}
	ln.mu.RUnlock()
	return snapshot
}

func (ln *labelName) Add(batch []*controller.PrometheusLabelName) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	for _, item := range batch {
		ln.pendingNameToID[item.GetName()] = int(item.GetId())
	}
}

func (ln *labelName) refresh(args ...interface{}) error {
	items, err := ln.load()
	if err != nil {
		return err
	}
	ln.processLoadedData(items)
	return nil
}

func (ln *labelName) processLoadedData(items []*metadbmodel.PrometheusLabelName) {
	newActive := make(map[string]int, len(items))
	for _, item := range items {
		newActive[item.Name] = item.ID
	}

	ln.mu.Lock()
	pending := ln.pendingNameToID
	ln.pendingNameToID = make(map[string]int)
	ln.mu.Unlock()

	for k, v := range pending {
		newActive[k] = v
	}
	ln.replaceActive(newActive)
}

func (ln *labelName) load() ([]*metadbmodel.PrometheusLabelName, error) {
	var labelNames []*metadbmodel.PrometheusLabelName
	err := ln.org.DB.Select("id", "name").Find(&labelNames).Error
	return labelNames, err
}
