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

type LabelKey struct {
	Name  string
	Value string
}

func (k LabelKey) String() string {
	return k.Name + "-" + k.Value
}

func NewLabelKey(name, value string) LabelKey {
	return LabelKey{
		Name:  name,
		Value: value,
	}
}

type label struct {
	org *common.ORG

	mu      sync.RWMutex
	keyToID map[LabelKey]int
}

func newLabel(org *common.ORG) *label {
	return &label{
		org:     org,
		keyToID: make(map[LabelKey]int),
	}
}

// GetKeyToID returns a snapshot copy of the keyToID map.
func (l *label) GetKeyToID() map[LabelKey]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make(map[LabelKey]int, len(l.keyToID))
	for k, v := range l.keyToID {
		result[k] = v
	}
	return result
}

func (l *label) GetIDByKey(key LabelKey) (int, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	id, ok := l.keyToID[key]
	return id, ok
}

func (l *label) Add(batch []*controller.PrometheusLabel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, item := range batch {
		k := NewLabelKey(item.GetName(), item.GetValue())
		l.keyToID[k] = int(item.GetId())
	}
}

// refresh rebuilds the entire cache from DB (snapshot-and-swap).
// This is the most critical optimization: the old ConcurrentMap append-only
// approach caused millions of String()+FNV hash+lock operations per refresh.
// Now we build a plain map without any locking during construction, then swap.
func (l *label) refresh(args ...interface{}) error {
	ls, err := l.load()
	if err != nil {
		return err
	}
	newMap := make(map[LabelKey]int, len(ls))
	for _, item := range ls {
		newMap[NewLabelKey(item.Name, item.Value)] = item.ID
	}
	l.mu.Lock()
	l.keyToID = newMap
	l.mu.Unlock()
	return nil
}

func (l *label) load() ([]*metadbmodel.PrometheusLabel, error) {
	var labels []*metadbmodel.PrometheusLabel
	err := l.org.DB.Select("id", "name", "value").Find(&labels).Error
	return labels, err
}
