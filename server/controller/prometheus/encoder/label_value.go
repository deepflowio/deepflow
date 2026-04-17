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
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelValue struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	strToID      map[string]int
}

func newLabelValue(org *common.ORG) *labelValue {
	return &labelValue{
		org:          org,
		resourceType: "label_value",
		strToID:      make(map[string]int),
	}
}

func (lv *labelValue) refresh(args ...interface{}) error {
	// Snapshot existing keys before querying DB, to identify entries added
	// by encode() during the query window (those must be preserved even if
	// not yet visible in the DB snapshot).
	lv.lock.Lock()
	preKeys := make(map[string]struct{}, len(lv.strToID))
	for k := range lv.strToID {
		preKeys[k] = struct{}{}
	}
	lv.lock.Unlock()

	var items []*metadbmodel.PrometheusLabelValue
	if err := lv.org.DB.Select("id", "value").Find(&items).Error; err != nil {
		log.Errorf("db query %s failed: %v", lv.resourceType, err, lv.org.LogPrefix)
		return err
	}
	newMap := make(map[string]int, len(items))
	for _, item := range items {
		newMap[item.Value] = item.ID
	}

	lv.lock.Lock()
	for k, v := range lv.strToID {
		if _, wasInSnapshot := preKeys[k]; !wasInSnapshot {
			// Written by encode() after the snapshot; may not be in the DB
			// snapshot yet, so preserve it to avoid a spurious cache miss.
			newMap[k] = v
		}
	}
	lv.strToID = newMap
	lv.lock.Unlock()
	return nil
}

func (lv *labelValue) encode(strs []string) ([]*controller.PrometheusLabelValue, error) {
	lv.lock.Lock()
	defer lv.lock.Unlock()

	resp := make([]*controller.PrometheusLabelValue, 0)
	dbToAdd := make([]*metadbmodel.PrometheusLabelValue, 0)
	for i := range strs {
		str := strs[i]
		if id, ok := lv.getID(str); ok {
			resp = append(resp, &controller.PrometheusLabelValue{Value: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &metadbmodel.PrometheusLabelValue{Value: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}

	err := addBatch(lv.org.DB, dbToAdd, lv.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", lv.resourceType, err.Error(), lv.org.LogPrefix)
		return nil, err
	}
	for i := range dbToAdd {
		lv.store(dbToAdd[i])
		resp = append(resp, &controller.PrometheusLabelValue{Value: &dbToAdd[i].Value, Id: proto.Uint32(uint32(dbToAdd[i].ID))})
	}
	return resp, nil
}

func (lv *labelValue) getID(str string) (int, bool) {
	id, ok := lv.strToID[str]
	return id, ok
}

func (lv *labelValue) store(item *metadbmodel.PrometheusLabelValue) {
	lv.strToID[item.Value] = item.ID
}
