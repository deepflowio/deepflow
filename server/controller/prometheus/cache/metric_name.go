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

type metricName struct {
	org *common.ORG

	mu       sync.RWMutex
	nameToID map[string]int
	idToName map[int]string
}

func newMetricName(org *common.ORG) *metricName {
	return &metricName{
		org:      org,
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}
}

// GetNameToID returns a snapshot copy of the nameToID map.
func (mn *metricName) GetNameToID() map[string]int {
	mn.mu.RLock()
	defer mn.mu.RUnlock()
	result := make(map[string]int, len(mn.nameToID))
	for k, v := range mn.nameToID {
		result[k] = v
	}
	return result
}

func (mn *metricName) GetIDByName(n string) (int, bool) {
	mn.mu.RLock()
	defer mn.mu.RUnlock()
	id, ok := mn.nameToID[n]
	return id, ok
}

func (mn *metricName) GetNameByID(id int) (string, bool) {
	mn.mu.RLock()
	defer mn.mu.RUnlock()
	name, ok := mn.idToName[id]
	return name, ok
}

func (mn *metricName) Add(batch []*controller.PrometheusMetricName) {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	for _, item := range batch {
		mn.nameToID[item.GetName()] = int(item.GetId())
		mn.idToName[int(item.GetId())] = item.GetName()
	}
}

// refresh rebuilds the entire cache from DB (snapshot-and-swap).
// Old entries not present in DB are naturally discarded, solving the memory leak.
func (mn *metricName) refresh(args ...interface{}) error {
	metricNames, err := mn.load()
	if err != nil {
		return err
	}
	newN2I := make(map[string]int, len(metricNames))
	newI2N := make(map[int]string, len(metricNames))
	for _, item := range metricNames {
		newN2I[item.Name] = item.ID
		newI2N[item.ID] = item.Name
	}
	mn.mu.Lock()
	mn.nameToID = newN2I
	mn.idToName = newI2N
	mn.mu.Unlock()
	return nil
}

func (mn *metricName) load() ([]*metadbmodel.PrometheusMetricName, error) {
	var metricNames []*metadbmodel.PrometheusMetricName
	err := mn.org.DB.Select("id", "name").Find(&metricNames).Error
	return metricNames, err
}
