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

type labelValue struct {
	org *common.ORG

	mu        sync.RWMutex
	valueToID map[string]int
}

func newLabelValue(org *common.ORG) *labelValue {
	return &labelValue{
		org:       org,
		valueToID: make(map[string]int),
	}
}

func (lv *labelValue) GetIDByValue(v string) (int, bool) {
	lv.mu.RLock()
	defer lv.mu.RUnlock()
	id, ok := lv.valueToID[v]
	return id, ok
}

// GetValueToID returns a snapshot copy of the valueToID map.
func (lv *labelValue) GetValueToID() map[string]int {
	lv.mu.RLock()
	defer lv.mu.RUnlock()
	result := make(map[string]int, len(lv.valueToID))
	for k, v := range lv.valueToID {
		result[k] = v
	}
	return result
}

func (lv *labelValue) Add(batch []*controller.PrometheusLabelValue) {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	for _, item := range batch {
		lv.valueToID[item.GetValue()] = int(item.GetId())
	}
}

// refresh rebuilds the entire cache from DB (snapshot-and-swap).
func (lv *labelValue) refresh(args ...interface{}) error {
	labelValues, err := lv.load()
	if err != nil {
		return err
	}
	newV2I := make(map[string]int, len(labelValues))
	for _, item := range labelValues {
		newV2I[item.Value] = item.ID
	}
	lv.mu.Lock()
	lv.valueToID = newV2I
	lv.mu.Unlock()
	return nil
}

func (lv *labelValue) load() ([]*metadbmodel.PrometheusLabelValue, error) {
	var labelValues []*metadbmodel.PrometheusLabelValue
	err := lv.org.DB.Select("id", "value").Find(&labelValues).Error
	return labelValues, err
}
