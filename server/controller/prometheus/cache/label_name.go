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
	org     *common.ORG
	active  atomic.Value // map[string]int
	activeR atomic.Value // map[int]string (reverse, rebuilt on refresh)

	mu              sync.RWMutex
	pendingNameToID map[string]int
	pendingIDToName map[int]string
}

func newLabelName(org *common.ORG) *labelName {
	ln := &labelName{
		org:             org,
		pendingNameToID: make(map[string]int),
		pendingIDToName: make(map[int]string),
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

func (ln *labelName) getActiveR() map[int]string {
	if activeR := ln.activeR.Load(); activeR != nil {
		return activeR.(map[int]string)
	}
	return map[int]string{}
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

func (ln *labelName) GetID(str string) (int, bool) {
	return ln.GetIDByName(str)
}

func (ln *labelName) setID(str string, id int) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	ln.pendingNameToID[str] = id
}

func (ln *labelName) Add(batch []*metadbmodel.PrometheusLabelName) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	for _, item := range batch {
		ln.pendingNameToID[item.Name] = item.ID
		ln.pendingIDToName[item.ID] = item.Name
	}
}

func (ln *labelName) AddFromGrpc(batch []*controller.PrometheusLabelName) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	for _, item := range batch {
		name := item.GetName()
		id := int(item.GetId())
		ln.pendingNameToID[name] = id
		ln.pendingIDToName[id] = name
	}
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

func (ln *labelName) GetNameByID(id int) (string, bool) {
	if activeR := ln.getActiveR(); activeR != nil {
		name, ok := activeR[id]
		if ok {
			return name, ok
		}
	}

	ln.mu.RLock()
	defer ln.mu.RUnlock()
	name, ok := ln.pendingIDToName[id]
	return name, ok
}

func (ln *labelName) refresh(args ...interface{}) error {
	var count int64
	if err := ln.org.DB.Model(&metadbmodel.PrometheusLabelName{}).Count(&count).Error; err != nil {
		return err
	}

	rows, err := ln.org.DB.Model(&metadbmodel.PrometheusLabelName{}).Select("id", "name").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newActive := make(map[string]int, count)
	newActiveR := make(map[int]string, count)
	for rows.Next() {
		var id int
		var name string
		if scanErr := rows.Scan(&id, &name); scanErr != nil {
			log.Errorf("stream scan prometheus_label_name interrupted: %v", scanErr, ln.org.LogPrefix)
			return scanErr
		}
		newActive[name] = id
		newActiveR[id] = name
	}
	if err := rows.Err(); err != nil {
		log.Errorf("stream read prometheus_label_name error: %v", err, ln.org.LogPrefix)
		return err
	}

	ln.mu.Lock()
	pending := ln.pendingNameToID
	pendingR := ln.pendingIDToName
	ln.pendingNameToID = make(map[string]int)
	ln.pendingIDToName = make(map[int]string)
	ln.mu.Unlock()

	for k, v := range pending {
		newActive[k] = v
	}
	for k, v := range pendingR {
		newActiveR[k] = v
	}
	ln.activeR.Store(newActiveR)
	ln.replaceActive(newActive)
	return nil
}
