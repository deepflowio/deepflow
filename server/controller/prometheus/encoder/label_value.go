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

type labelValue struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	cache        cache.PrometheusCache
}

func newLabelValue(org *common.ORG) *labelValue {
	c, _ := cache.GetCache(org.ID)
	return &labelValue{
		org:          org,
		resourceType: "label_value",
		cache:        c,
	}
}

func (lv *labelValue) refresh(args ...interface{}) error {
	lv.lock.Lock()
	defer lv.lock.Unlock()
	return lv.cache.Refresh()
}

func (lv *labelValue) encode(strs []string) ([]*controller.PrometheusLabelValue, error) {
	lv.lock.Lock()
	defer lv.lock.Unlock()

	resp := make([]*controller.PrometheusLabelValue, 0)
	var dbToAdd []*metadbmodel.PrometheusLabelValue
	for i := range strs {
		str := strs[i]
		if id, ok := lv.cache.GetLabelValueID(str); ok {
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
	lv.cache.AddLabelValues(dbToAdd)
	for i := range dbToAdd {
		resp = append(resp, &controller.PrometheusLabelValue{Value: &dbToAdd[i].Value, Id: proto.Uint32(uint32(dbToAdd[i].ID))})
	}
	return resp, nil
}
