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

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type metricName struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	cache        cache.PrometheusCache
	ascIDAllocator
}

func newMetricName(org *common.ORG, max int) *metricName {
	c, _ := cache.GetCache(org.ID)
	mn := &metricName{
		org:          org,
		resourceType: "metric_name",
		cache:        c,
	}
	mn.ascIDAllocator = newAscIDAllocator(org, mn.resourceType, 1, max)
	mn.rawDataProvider = mn
	return mn
}

func (mn *metricName) getID(str string) (int, bool) {
	return mn.cache.GetMetricNameID(str)
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
	dbToAdd := make([]*metadbmodel.PrometheusMetricName, 0)
	for i := range strs {
		str := strs[i]
		if id, ok := mn.cache.GetMetricNameID(str); ok {
			resp = append(resp, &controller.PrometheusMetricName{Name: &str, Id: proto.Uint32(uint32(id))})
			continue
		}
		dbToAdd = append(dbToAdd, &metadbmodel.PrometheusMetricName{Name: str})
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

	// Update cache using model structs directly to avoid redundant protobuf construction
	for i := range dbToAdd {
		id := dbToAdd[i].ID
		str := dbToAdd[i].Name
		resp = append(resp, &controller.PrometheusMetricName{Name: &str, Id: proto.Uint32(uint32(id))})
	}
	mn.cache.AddMetricNames(dbToAdd)
	return resp, nil
}

func (mn *metricName) load() (ids mapset.Set[int], err error) {
	var items []*metadbmodel.PrometheusMetricName
	err = mn.org.DB.Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", mn.resourceType, err, mn.org.LogPrefix)
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(item.ID)
		// Cache is refreshed separately, do not set here
	}
	return inUseIDsSet, nil
}

func (mn *metricName) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*metadbmodel.PrometheusMetricName
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
