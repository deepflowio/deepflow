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
	"fmt"
	"sync"
	"sync/atomic"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// LabelKey identifies a prometheus_label by its foreign-key IDs, avoiding
// repeated string storage for the hot in-memory map.
type LabelKey struct {
	NameID  int
	ValueID int
}

func (k LabelKey) String() string {
	return fmt.Sprintf("%d-%d", k.NameID, k.ValueID)
}

func NewLabelKey(nameID, valueID int) LabelKey {
	return LabelKey{NameID: nameID, ValueID: valueID}
}

// LabelCacheEntry is used by callers to batch-add newly encoded labels to
// the cache after the name_id and value_id are known.
type LabelCacheEntry struct {
	NameID  int
	ValueID int
	LabelID int
}

type label struct {
	org *common.ORG

	active  atomic.Value
	pending map[LabelKey]int
	mu      sync.RWMutex
}

func newLabel(org *common.ORG) *label {
	l := &label{
		org:     org,
		pending: make(map[LabelKey]int),
	}
	l.active.Store(make(map[LabelKey]int))
	return l
}

func (l *label) getActive() map[LabelKey]int {
	if active := l.active.Load(); active != nil {
		return active.(map[LabelKey]int)
	}
	return map[LabelKey]int{}
}

func cloneLabelMap(src map[LabelKey]int, extra int) map[LabelKey]int {
	dst := make(map[LabelKey]int, len(src)+extra)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (l *label) replaceActive(newActive map[LabelKey]int) {
	l.active.Store(newActive)
}

func (l *label) GetKeyToID() map[LabelKey]int {
	active := l.getActive()

	l.mu.RLock()
	pendingLen := len(l.pending)
	snapshot := cloneLabelMap(active, pendingLen)
	for key, value := range l.pending {
		snapshot[key] = value
	}
	l.mu.RUnlock()

	return snapshot
}

func (l *label) GetIDByKey(key LabelKey) (int, bool) {
	if item, ok := l.getActive()[key]; ok {
		return item, true
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	if item, ok := l.pending[key]; ok {
		return item, true
	}
	return 0, false
}

// Add inserts newly encoded labels into the pending map. Callers must resolve
// name_id and value_id before calling (see LabelCacheEntry).
func (l *label) Add(entries []LabelCacheEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range entries {
		l.pending[NewLabelKey(e.NameID, e.ValueID)] = e.LabelID
	}
}

func (l *label) refresh(args ...interface{}) error {
	var count int64
	if err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Count(&count).Error; err != nil {
		return err
	}

	rows, err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Select("id", "name_id", "value_id").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newActive := make(map[LabelKey]int, count)
	for rows.Next() {
		var id, nameID, valueID int
		if scanErr := rows.Scan(&id, &nameID, &valueID); scanErr != nil {
			log.Errorf("stream scan prometheus_label interrupted: %v", scanErr, l.org.LogPrefix)
			return scanErr
		}
		newActive[NewLabelKey(nameID, valueID)] = id
	}
	if err := rows.Err(); err != nil {
		log.Errorf("stream read prometheus_label error: %v", err, l.org.LogPrefix)
		return err
	}

	l.mu.Lock()
	pending := l.pending
	l.pending = make(map[LabelKey]int)
	for key, value := range pending {
		newActive[key] = value
	}
	l.mu.Unlock()

	l.replaceActive(newActive)
	return nil
}
