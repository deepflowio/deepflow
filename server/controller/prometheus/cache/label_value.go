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

type labelValue struct {
	org *common.ORG

	active  atomic.Value
	pending map[string]int
	mu      sync.RWMutex
}

func (lv *labelValue) replaceActive(newActive map[string]int) {
	lv.active.Store(newActive)
}

func newLabelValue(org *common.ORG) *labelValue {
	lv := &labelValue{
		org:     org,
		active:  atomic.Value{},
		pending: make(map[string]int),
	}
	lv.active.Store(make(map[string]int))
	return lv
}

func (lv *labelValue) getActive() map[string]int {
	if active := lv.active.Load(); active != nil {
		return active.(map[string]int)
	}
	return map[string]int{}
}

func cloneValueMap(src map[string]int, extra int) map[string]int {
	dst := make(map[string]int, len(src)+extra)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (lv *labelValue) GetIDByValue(v string) (int, bool) {
	if item, ok := lv.getActive()[v]; ok {
		return item, true
	}

	lv.mu.RLock()
	defer lv.mu.RUnlock()
	if item, ok := lv.pending[v]; ok {
		return item, true
	}
	return 0, false
}

func (lv *labelValue) GetValueToID() map[string]int {
	active := lv.getActive()

	lv.mu.RLock()
	pendingLen := len(lv.pending)
	snapshot := cloneValueMap(active, pendingLen)
	for key, value := range lv.pending {
		snapshot[key] = value
	}
	lv.mu.RUnlock()

	return snapshot
}

func (lv *labelValue) Add(batch []*controller.PrometheusLabelValue) {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	for _, item := range batch {
		lv.pending[item.GetValue()] = int(item.GetId())
	}
}

func (lv *labelValue) refresh(args ...interface{}) error {
	data, err := lv.load()
	if err != nil {
		return err
	}

	newActive := lv.processLoadedData(data)

	lv.mu.Lock()
	pending := lv.pending
	lv.pending = make(map[string]int)
	for key, value := range pending {
		newActive[key] = value
	}
	lv.mu.Unlock()

	lv.replaceActive(newActive)
	return nil
}

func (lv *labelValue) processLoadedData(data []*metadbmodel.PrometheusLabelValue) map[string]int {
	newActive := make(map[string]int, len(data))
	for _, item := range data {
		newActive[item.Value] = item.ID
	}
	return newActive
}

func (lv *labelValue) load() ([]*metadbmodel.PrometheusLabelValue, error) {
	var labelValues []*metadbmodel.PrometheusLabelValue
	err := lv.org.DB.Find(&labelValues).Error
	return labelValues, err
}
