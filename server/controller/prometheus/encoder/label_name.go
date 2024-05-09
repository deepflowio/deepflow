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

	"github.com/cornelk/hashmap"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type labelName struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	strToID      *hashmap.Map[string, int]
	ascIDAllocator
}

func newLabelName(org *common.ORG, max int) *labelName {
	ln := &labelName{
		org:          org,
		resourceType: "label_name",
		strToID:      hashmap.New[string, int](),
	}
	ln.ascIDAllocator = newAscIDAllocator(org, ln.resourceType, 1, max)
	ln.rawDataProvider = ln
	return ln
}

func (mn *labelName) getID(str string) (int, bool) {
	return mn.strToID.Get(str)
}

func (ln *labelName) refresh(args ...interface{}) error {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	return ln.ascIDAllocator.refresh()
}

func (ln *labelName) encode(strs []string) ([]*controller.PrometheusLabelName, error) {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	resp := make([]*controller.PrometheusLabelName, 0)
	var dbToAdd []*mysql.PrometheusLabelName
	for i := range strs {
		str := strs[i]
		if id, ok := ln.strToID.Get(str); ok {
			resp = append(resp, &controller.PrometheusLabelName{Name: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusLabelName{Name: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}
	ids, err := ln.allocate(len(dbToAdd))
	if err != nil {
		return nil, err
	}
	for i := range ids {
		dbToAdd[i].ID = ids[i]
	}
	err = addBatch(ln.org.DB, dbToAdd, ln.resourceType)
	if err != nil {
		log.Error(ln.org.Logf("add %s error: %s", ln.resourceType, err.Error()))
		return nil, err
	}
	for i := range dbToAdd {
		id := dbToAdd[i].ID
		str := dbToAdd[i].Name
		ln.strToID.Set(str, id)
		resp = append(resp, &controller.PrometheusLabelName{Name: &str, Id: proto.Uint32(uint32(id))})
	}
	return resp, nil
}

func (ln *labelName) load() (ids mapset.Set[int], err error) {
	var items []*mysql.PrometheusLabelName
	err = ln.org.DB.Find(&items).Error
	if err != nil {
		log.Error(ln.org.Logf("db query %s failed: %v", ln.resourceType, err))
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(item.ID)
		ln.strToID.Set(item.Name, item.ID)
	}
	return inUseIDsSet, nil
}

func (ln *labelName) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*mysql.PrometheusLabelName
	err = ln.org.DB.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Error(ln.org.Logf("db query %s failed: %v", ln.resourceType, err))
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, item.ID)
		}
		log.Info(ln.org.Logf("%s ids: %+v are in use.", ln.resourceType, inUseIDs))
	}
	return
}
