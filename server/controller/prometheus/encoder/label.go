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
	labelName    *labelName
	labelValue   *labelValue
}

func newLabel(org *common.ORG, ln *labelName, lv *labelValue) *label {
	return &label{
		org:          org,
		resourceType: "label",
		labelKeyToID: make(map[cache.LabelKey]int),
		labelName:    ln,
		labelValue:   lv,
	}
}

func (l *label) store(item *metadbmodel.PrometheusLabel) {
	l.labelKeyToID[cache.NewLabelKey(item.NameID, item.ValueID)] = item.ID
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

	log.Info("TODO start")
	rows, err := l.org.DB.Model(&metadbmodel.PrometheusLabel{}).Select("id", "name_id", "value_id").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newMap := make(map[cache.LabelKey]int)
	for rows.Next() {
		var id, nameID, valueID int
		if scanErr := rows.Scan(&id, &nameID, &valueID); scanErr != nil {
			return scanErr
		}
		newMap[cache.NewLabelKey(nameID, valueID)] = id
	}
	if err := rows.Err(); err != nil {
		return err
	}

	log.Info("TODO end")
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

	type pendingLabel struct {
		item *metadbmodel.PrometheusLabel
	}

	resp := make([]*controller.PrometheusLabel, 0)
	var pending []pendingLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		nameID, okN := l.labelName.getID(n)
		valueID, okV := l.labelValue.getID(v)
		if !okN || !okV {
			// Name or value not yet encoded — skip; the next encode round
			// (after the caller retries) will succeed once they are present.
			log.Warningf("label (%s=%s): name_id or value_id not found, skipping", n, v, l.org.LogPrefix)
			continue
		}
		if id, ok := l.getID(cache.NewLabelKey(nameID, valueID)); ok {
			resp = append(resp, &controller.PrometheusLabel{
				Id:      proto.Uint32(uint32(id)),
				NameId:  proto.Uint32(uint32(nameID)),
				ValueId: proto.Uint32(uint32(valueID)),
			})
			continue
		}
		pending = append(pending, pendingLabel{
			item: &metadbmodel.PrometheusLabel{NameID: nameID, ValueID: valueID},
		})
	}

	dbToAdd := make([]*metadbmodel.PrometheusLabel, len(pending))
	for i := range pending {
		dbToAdd[i] = pending[i].item
	}
	if err := addBatch(l.org.DB, dbToAdd, l.resourceType); err != nil {
		log.Errorf("add %s error: %s", l.resourceType, err.Error(), l.org.LogPrefix)
		return nil, err
	}
	for i, p := range pending {
		l.store(dbToAdd[i])
		resp = append(resp, &controller.PrometheusLabel{
			Id:      proto.Uint32(uint32(dbToAdd[i].ID)),
			NameId:  proto.Uint32(uint32(p.item.NameID)),
			ValueId: proto.Uint32(uint32(p.item.ValueID)),
		})
	}
	return resp, nil
}
