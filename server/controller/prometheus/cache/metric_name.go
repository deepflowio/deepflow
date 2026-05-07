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

type metricName struct {
	org *common.ORG

	active  atomic.Value // map[string]int (nameToID)
	activeR atomic.Value // map[int]string (idToName)

	mu              sync.RWMutex
	pendingNameToID map[string]int
}

func newMetricName(org *common.ORG) *metricName {
	mn := &metricName{
		org:             org,
		pendingNameToID: make(map[string]int),
	}
	mn.active.Store(make(map[string]int))
	mn.activeR.Store(make(map[int]string))
	return mn
}

func (mn *metricName) getActive() map[string]int {
	if active := mn.active.Load(); active != nil {
		return active.(map[string]int)
	}
	return map[string]int{}
}

func (mn *metricName) replaceActive(newActive map[string]int) {
	mn.active.Store(newActive)
}

func (mn *metricName) GetID(str string) (int, bool) {
	if id, ok := mn.getActive()[str]; ok {
		return id, ok
	}

	mn.mu.RLock()
	defer mn.mu.RUnlock()
	id, ok := mn.pendingNameToID[str]
	return id, ok
}

func (mn *metricName) GetIDByName(name string) (int, bool) {
	return mn.GetID(name)
}

func (mn *metricName) GetNameByID(id int) (string, bool) {
	if activeR := mn.activeR.Load(); activeR != nil {
		name, ok := activeR.(map[int]string)[id]
		return name, ok
	}
	return "", false
}

func (mn *metricName) setID(str string, id int) {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	mn.pendingNameToID[str] = id
}

func (mn *metricName) Add(batch []*metadbmodel.PrometheusMetricName) {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	for _, item := range batch {
		mn.pendingNameToID[item.Name] = item.ID
	}
}

func (mn *metricName) AddFromGrpc(batch []*controller.PrometheusMetricName) {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	for _, item := range batch {
		mn.pendingNameToID[item.GetName()] = int(item.GetId())
	}
}

func (mn *metricName) GetNameToID() map[string]int {
	active := mn.getActive()

	mn.mu.RLock()
	snapshot := make(map[string]int, len(active)+len(mn.pendingNameToID))
	for k, v := range active {
		snapshot[k] = v
	}
	for k, v := range mn.pendingNameToID {
		snapshot[k] = v
	}
	mn.mu.RUnlock()

	return snapshot
}

func (mn *metricName) refresh(args ...interface{}) error {
	items, err := mn.load()
	if err != nil {
		return err
	}
	mn.processLoadedData(items)
	return nil
}

func (mn *metricName) processLoadedData(items []*metadbmodel.PrometheusMetricName) {
	newActive := make(map[string]int, len(items))
	newActiveR := make(map[int]string, len(items))
	for _, item := range items {
		newActive[item.Name] = item.ID
		newActiveR[item.ID] = item.Name
	}

	mn.mu.Lock()
	pending := mn.pendingNameToID
	mn.pendingNameToID = make(map[string]int)
	mn.mu.Unlock()

	for k, v := range pending {
		newActive[k] = v
	}

	mn.activeR.Store(newActiveR)
	mn.replaceActive(newActive)
}

func (mn *metricName) load() ([]*metadbmodel.PrometheusMetricName, error) {
	var items []*metadbmodel.PrometheusMetricName
	err := mn.org.DB.Select("id", "name").Find(&items).Error
	return items, err
}
