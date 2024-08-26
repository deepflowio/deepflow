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
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type metricName struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	strToID      *hashmap.Map[string, int]
	ascIDAllocator
}

func newMetricName(org *common.ORG, max int) *metricName {
	mn := &metricName{
		org:          org,
		resourceType: "metric_name",
		strToID:      hashmap.New[string, int](),
	}
	mn.ascIDAllocator = newAscIDAllocator(org, mn.resourceType, 1, max)
	mn.rawDataProvider = mn
	return mn
}

func (mn *metricName) getID(str string) (int, bool) {
	return mn.strToID.Get(str)
}

func (mn *metricName) refresh(args ...interface{}) error {
	mn.lock.Lock()
	defer mn.lock.Unlock()

	return mn.ascIDAllocator.refresh()
}

func (mn *metricName) encode(strs []string) ([]*controller.PrometheusMetricName, error) {
	mn.lock.Lock()
	defer mn.lock.Unlock()

	resp := make([]*controller.PrometheusMetricName, 0)
	dbToAdd := make([]*mysqlmodel.PrometheusMetricName, 0)
	for i := range strs {
		str := strs[i]
		if id, ok := mn.strToID.Get(str); ok {
			resp = append(resp, &controller.PrometheusMetricName{Name: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &mysqlmodel.PrometheusMetricName{Name: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}
	ids, err := mn.allocate(len(dbToAdd))
	if err != nil {
		return nil, err
	}
	for i := range dbToAdd {
		dbToAdd[i].ID = ids[i]
	}
	err = addBatch(mn.org.DB, dbToAdd, mn.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", mn.resourceType, err.Error(), mn.org.LogPrefix)
		return nil, err
	}
	for i := range dbToAdd {
		id := dbToAdd[i].ID
		str := dbToAdd[i].Name
		mn.strToID.Set(str, id)
		resp = append(resp, &controller.PrometheusMetricName{Name: &str, Id: proto.Uint32(uint32(id))})
	}
	return resp, nil
}

func (mn *metricName) load() (ids mapset.Set[int], err error) {
	var items []*mysqlmodel.PrometheusMetricName
	err = mn.org.DB.Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", mn.resourceType, err, mn.org.LogPrefix)
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(item.ID)
		mn.strToID.Set(item.Name, item.ID)
	}
	return inUseIDsSet, nil
}

func (mn *metricName) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*mysqlmodel.PrometheusMetricName
	err = mn.org.DB.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", mn.resourceType, err, mn.org.LogPrefix)
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, item.ID)
		}
		log.Infof("%s ids: %+v are in use.", mn.resourceType, inUseIDs, mn.org.LogPrefix)
	}
	return
}
