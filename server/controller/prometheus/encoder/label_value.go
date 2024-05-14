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

	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelValue struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	strToID      sync.Map
}

func newLabelValue(org *common.ORG) *labelValue {
	return &labelValue{
		org:          org,
		resourceType: "label_value",
	}
}

func (lv *labelValue) refresh(args ...interface{}) error {
	var items []*mysql.PrometheusLabelValue
	err := lv.org.DB.Unscoped().Find(&items).Error
	if err != nil {
		log.Error(lv.org.Logf("db query %s failed: %v", lv.resourceType, err))
		return err
	}
	for _, item := range items {
		lv.store(item)
	}
	return nil
}

func (lv *labelValue) encode(strs []string) ([]*controller.PrometheusLabelValue, error) {
	lv.lock.Lock()
	defer lv.lock.Unlock()

	resp := make([]*controller.PrometheusLabelValue, 0)
	dbToAdd := make([]*mysql.PrometheusLabelValue, 0)
	for i := range strs {
		str := strs[i]
		if id, ok := lv.getID(str); ok {
			resp = append(resp, &controller.PrometheusLabelValue{Value: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusLabelValue{Value: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}

	err := addBatch(lv.org.DB, dbToAdd, lv.resourceType)
	if err != nil {
		log.Error(lv.org.Logf("add %s error: %s", lv.resourceType, err.Error()))
		return nil, err
	}
	for i := range dbToAdd {
		lv.store(dbToAdd[i])
		resp = append(resp, &controller.PrometheusLabelValue{Value: &dbToAdd[i].Value, Id: proto.Uint32(uint32(dbToAdd[i].ID))})
	}
	return resp, nil
}

func (lv *labelValue) getID(str string) (int, bool) {
	if item, ok := lv.strToID.Load(str); ok {
		return item.(int), true
	}
	return 0, false
}

func (lv *labelValue) store(item *mysql.PrometheusLabelValue) {
	lv.strToID.Store(item.Value, item.ID)
}
