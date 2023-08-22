/**
 * Copyright (c) 2023 Yunshan Networks
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

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type labelValue struct {
	lock         sync.Mutex
	resourceType string
	strToID      map[string]int
	ascIDAllocator
}

func newLabelValue(max int) *labelValue {
	lv := &labelValue{
		resourceType: "label_value",
		strToID:      make(map[string]int),
	}
	lv.ascIDAllocator = newAscIDAllocator(lv.resourceType, 1, max)
	lv.rawDataProvider = lv
	return lv
}

func (lv *labelValue) refresh(args ...interface{}) error {
	lv.lock.Lock()
	defer lv.lock.Unlock()

	return lv.ascIDAllocator.refresh()
}

func (lv *labelValue) encode(strs []string) ([]*controller.PrometheusLabelValue, error) {
	lv.lock.Lock()
	defer lv.lock.Unlock()

	resp := make([]*controller.PrometheusLabelValue, 0)
	dbToAdd := make([]*mysql.PrometheusLabelValue, 0)
	for i := range strs {
		str := strs[i]
		if id, ok := lv.strToID[str]; ok {
			resp = append(resp, &controller.PrometheusLabelValue{Value: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusLabelValue{Value: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}
	ids, err := lv.allocate(len(dbToAdd))
	if err != nil {
		return nil, err
	}
	for i := range dbToAdd {
		dbToAdd[i].ID = ids[i]
	}
	err = addBatch(dbToAdd, lv.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", lv.resourceType, err.Error())
		return nil, err
	}
	for i := range dbToAdd {
		id := dbToAdd[i].ID
		str := dbToAdd[i].Value
		lv.strToID[str] = id
		resp = append(resp, &controller.PrometheusLabelValue{Value: &str, Id: proto.Uint32(uint32(id))})
	}
	return resp, nil
}

func (lv *labelValue) load() (ids mapset.Set[int], err error) {
	var items []*mysql.PrometheusLabelValue
	err = mysql.Db.Unscoped().Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", lv.resourceType, err)
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(item.ID)
		lv.strToID[item.Value] = item.ID
	}
	return inUseIDsSet, nil
}

func (lv *labelValue) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*mysql.PrometheusLabelValue
	err = mysql.Db.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", lv.resourceType, err)
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, item.ID)
		}
		log.Infof("%s ids: %+v are in use.", lv.resourceType, inUseIDs)
	}
	return
}
