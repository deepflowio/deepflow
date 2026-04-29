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

	isRefreshing bool
	pendingKeys  map[string]int
}

func newLabelValue(org *common.ORG) *labelValue {
	return &labelValue{
		org:          org,
		resourceType: "label_value",
		strToID:      make(map[string]int),
	}
}

func (lv *labelValue) MarkRefresh() {
	lv.lock.Lock()
	defer lv.lock.Unlock()
	lv.isRefreshing = true
	lv.pendingKeys = make(map[string]int)
}

func (lv *labelValue) MarkRefreshDone() {
	lv.lock.Lock()
	defer lv.lock.Unlock()
	lv.isRefreshing = false
	lv.pendingKeys = nil
}

func (lv *labelValue) refresh(args ...interface{}) error {
	lv.MarkRefresh()
	defer lv.MarkRefreshDone()

	log.Info("TODO start")

	var count int64
	if err := lv.org.DB.Model(&metadbmodel.PrometheusLabelValue{}).Count(&count).Error; err != nil {
		log.Errorf("db query %s failed: %v", lv.resourceType, err, lv.org.LogPrefix)
		return err
	}

	rows, err := lv.org.DB.Model(&metadbmodel.PrometheusLabelValue{}).Select("id", "value").Rows()
	if err != nil {
		log.Errorf("db query %s failed: %v", lv.resourceType, err, lv.org.LogPrefix)
		return err
	}
	defer rows.Close()

	newMap := make(map[string]int, count)
	for rows.Next() {
		var id int
		var value string
		if scanErr := rows.Scan(&id, &value); scanErr != nil {
			log.Errorf("db stream scan %s interrupted: %v", lv.resourceType, scanErr, lv.org.LogPrefix)
			return scanErr
		}
		newMap[value] = id
	}
	if err := rows.Err(); err != nil {
		log.Errorf("db stream %s error: %v", lv.resourceType, err, lv.org.LogPrefix)
		return err
	}

	lv.lock.Lock()
	for k, v := range lv.pendingKeys {
		newMap[k] = v
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
		if id, ok := lv.getIDLocked(str); ok {
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

// getIDLocked reads strToID without acquiring lv.lock. Caller must hold lv.lock.
func (lv *labelValue) getIDLocked(str string) (int, bool) {
	id, ok := lv.strToID[str]
	return id, ok
}

// getID is safe for concurrent callers; it acquires lv.lock internally.
func (lv *labelValue) getID(str string) (int, bool) {
	lv.lock.Lock()
	defer lv.lock.Unlock()
	return lv.getIDLocked(str)
}

func (lv *labelValue) store(item *metadbmodel.PrometheusLabelValue) {
	lv.strToID[item.Value] = item.ID

	if lv.isRefreshing {
		lv.pendingKeys[item.Value] = item.ID
	}
}
