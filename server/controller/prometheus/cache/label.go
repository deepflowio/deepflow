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

// LabelKey is the external string-based key used by callers.
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

// IDLabelKey is the internal int-based key used for compact map storage.
// Avoids storing millions of duplicate string objects in memory.
type IDLabelKey struct {
	NameID  int
	ValueID int
}

type label struct {
	org *common.ORG

	labelName  *labelName
	labelValue *labelValue

	active  atomic.Value // map[IDLabelKey]int
	pending map[IDLabelKey]int
	mu      sync.RWMutex
}

func newLabel(org *common.ORG, ln *labelName, lv *labelValue) *label {
	l := &label{
		org:        org,
		labelName:  ln,
		labelValue: lv,
		pending:    make(map[IDLabelKey]int),
	}
	l.active.Store(make(map[IDLabelKey]int))
	return l
}

func (l *label) getActive() map[IDLabelKey]int {
	if active := l.active.Load(); active != nil {
		return active.(map[IDLabelKey]int)
	}
	return map[IDLabelKey]int{}
}

func (l *label) replaceActive(newActive map[IDLabelKey]int) {
	l.active.Store(newActive)
}

// toIDKey converts a string-based LabelKey to an int-based IDLabelKey.
// Returns false if either name or value is not found in the caches.
func (l *label) toIDKey(key LabelKey) (IDLabelKey, bool) {
	nameID, ok := l.labelName.GetIDByName(key.Name)
	if !ok {
		return IDLabelKey{}, false
	}
	valueID, ok := l.labelValue.GetIDByValue(key.Value)
	if !ok {
		return IDLabelKey{}, false
	}
	return IDLabelKey{NameID: nameID, ValueID: valueID}, true
}

// GetKeyToID returns a snapshot of all labels as string-based LabelKey map.
// This is an infrequent operation (debug, full assembly); it converts
// internal IDLabelKey back to LabelKey using reverse lookups.
func (l *label) GetKeyToID() map[LabelKey]int {
	active := l.getActive()

	l.mu.RLock()
	pendingLen := len(l.pending)
	merged := make(map[IDLabelKey]int, len(active)+pendingLen)
	for k, v := range active {
		merged[k] = v
	}
	for k, v := range l.pending {
		merged[k] = v
	}
	l.mu.RUnlock()

	result := make(map[LabelKey]int, len(merged))
	for idk, id := range merged {
		name, ok1 := l.labelName.GetNameByID(idk.NameID)
		value, ok2 := l.labelValue.GetValueByID(idk.ValueID)
		if ok1 && ok2 {
			result[NewLabelKey(name, value)] = id
		}
	}
	return result
}

func (l *label) GetIDByKey(key LabelKey) (int, bool) {
	idk, ok := l.toIDKey(key)
	if !ok {
		return 0, false
	}

	if item, ok := l.getActive()[idk]; ok {
		return item, true
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	if item, ok := l.pending[idk]; ok {
		return item, true
	}
	return 0, false
}

func (l *label) Add(batch []*controller.PrometheusLabel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, item := range batch {
		nameID, ok1 := l.labelName.GetIDByName(item.GetName())
		valueID, ok2 := l.labelValue.GetIDByValue(item.GetValue())
		if ok1 && ok2 {
			l.pending[IDLabelKey{NameID: nameID, ValueID: valueID}] = int(item.GetId())
		}
	}
}

func (l *label) refresh(args ...interface{}) error {
	var count int64
	if err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Count(&count).Error; err != nil {
		return err
	}

	rows, err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Select("id", "name", "value").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newActive := make(map[IDLabelKey]int, count)
	for rows.Next() {
		var id int
		var name, value string
		if scanErr := rows.Scan(&id, &name, &value); scanErr != nil {
			log.Errorf("stream scan prometheus_label interrupted: %v", scanErr, l.org.LogPrefix)
			return scanErr
		}
		nameID, ok1 := l.labelName.GetIDByName(name)
		valueID, ok2 := l.labelValue.GetIDByValue(value)
		if ok1 && ok2 {
			newActive[IDLabelKey{NameID: nameID, ValueID: valueID}] = id
		}
	}
	if err := rows.Err(); err != nil {
		log.Errorf("stream read prometheus_label error: %v", err, l.org.LogPrefix)
		return err
	}

	l.mu.Lock()
	pending := l.pending
	l.pending = make(map[IDLabelKey]int)
	for key, value := range pending {
		newActive[key] = value
	}
	l.mu.Unlock()

	l.replaceActive(newActive)
	return nil
}
