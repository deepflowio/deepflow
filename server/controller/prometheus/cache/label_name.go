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

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelName struct {
	org *common.ORG

	mu       sync.RWMutex
	nameToID map[string]int
	idToName map[int]string
}

func newLabelName(org *common.ORG) *labelName {
	return &labelName{
		org:      org,
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}
}

func (ln *labelName) GetIDByName(n string) (int, bool) {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	id, ok := ln.nameToID[n]
	return id, ok
}

func (ln *labelName) GetNameByID(id int) (string, bool) {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	name, ok := ln.idToName[id]
	return name, ok
}

// GetNameToID returns a snapshot copy of the nameToID map.
func (ln *labelName) GetNameToID() map[string]int {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	result := make(map[string]int, len(ln.nameToID))
	for k, v := range ln.nameToID {
		result[k] = v
	}
	return result
}

func (ln *labelName) Add(batch []*controller.PrometheusLabelName) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	for _, item := range batch {
		ln.nameToID[item.GetName()] = int(item.GetId())
		ln.idToName[int(item.GetId())] = item.GetName()
	}
}

// refresh rebuilds the entire cache from DB (snapshot-and-swap).
func (ln *labelName) refresh(args ...interface{}) error {
	labelNames, err := ln.load()
	if err != nil {
		return err
	}
	newN2I := make(map[string]int, len(labelNames))
	newI2N := make(map[int]string, len(labelNames))
	for _, item := range labelNames {
		newN2I[item.Name] = item.ID
		newI2N[item.ID] = item.Name
	}
	ln.mu.Lock()
	ln.nameToID = newN2I
	ln.idToName = newI2N
	ln.mu.Unlock()
	return nil
}

func (ln *labelName) load() ([]*metadbmodel.PrometheusLabelName, error) {
	var labelNames []*metadbmodel.PrometheusLabelName
	err := ln.org.DB.Select("id", "name").Find(&labelNames).Error
	return labelNames, err
}
