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

package encoder

import (
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type label struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	labelKeyToID map[cache.LabelKey]int
}

func newLabel(org *common.ORG) *label {
	return &label{
		org:          org,
		resourceType: "label",
		labelKeyToID: make(map[cache.LabelKey]int),
	}
}

func (l *label) store(item *metadbmodel.PrometheusLabel) {
	l.labelKeyToID[cache.NewLabelKey(item.Name, item.Value)] = item.ID
}

func (l *label) getID(key cache.LabelKey) (int, bool) {
	id, ok := l.labelKeyToID[key]
	return id, ok
}

func (l *label) refresh(args ...interface{}) error {
	// Snapshot existing keys before querying DB, to identify entries added
	// by encode() during the query window (those must be preserved even if
	// not yet visible in the DB snapshot).
	l.lock.Lock()
	preKeys := make(map[cache.LabelKey]struct{}, len(l.labelKeyToID))
	for k := range l.labelKeyToID {
		preKeys[k] = struct{}{}
	}
	l.lock.Unlock()

	rows, err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Select("id", "name", "value").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newMap := make(map[cache.LabelKey]int)
	for rows.Next() {
		var id int
		var name, value string
		if scanErr := rows.Scan(&id, &name, &value); scanErr != nil {
			log.Errorf("db stream scan %s interrupted: %v", l.resourceType, scanErr, l.org.LogPrefix)
			return scanErr
		}
		newMap[cache.NewLabelKey(name, value)] = id
	}
	if err := rows.Err(); err != nil {
		log.Errorf("db stream %s error: %v", l.resourceType, err, l.org.LogPrefix)
		return err
	}

	l.lock.Lock()
	for k, v := range l.labelKeyToID {
		if _, wasInSnapshot := preKeys[k]; !wasInSnapshot {
			// Written by encode() after the snapshot; may not be in the DB
			// snapshot yet, so preserve it to avoid a spurious cache miss.
			newMap[k] = v
		}
	}
	l.labelKeyToID = newMap
	l.lock.Unlock()
	return nil
}

func (l *label) encode(toAdd []*controller.PrometheusLabelRequest) ([]*controller.PrometheusLabel, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	resp := make([]*controller.PrometheusLabel, 0)
	var dbToAdd []*metadbmodel.PrometheusLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		if id, ok := l.getID(cache.NewLabelKey(n, v)); ok {
			resp = append(resp, &controller.PrometheusLabel{
				Name:  &n,
				Value: &v,
				Id:    proto.Uint32(uint32(id)),
			})
			continue
		}
		dbToAdd = append(dbToAdd, &metadbmodel.PrometheusLabel{
			Name:  n,
			Value: v,
		})
	}

	err := addBatch(l.org.DB, dbToAdd, l.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", l.resourceType, err.Error(), l.org.LogPrefix)
		return nil, err
	}
	for _, item := range dbToAdd {
		l.store(item)
		resp = append(resp, &controller.PrometheusLabel{
			Name:  &item.Name,
			Value: &item.Value,
			Id:    proto.Uint32(uint32(item.ID)),
		})

	}
	return resp, nil
}
