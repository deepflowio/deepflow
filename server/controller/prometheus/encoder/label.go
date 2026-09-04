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
	cache        cache.PrometheusCache
}

func newLabel(org *common.ORG) *label {
	c, _ := cache.GetCache(org.ID)
	return &label{
		org:          org,
		resourceType: "label",
		cache:        c,
	}
}

func (l *label) refresh(args ...interface{}) error {
	return l.cache.Refresh(false)
}

func (l *label) encode(toAdd []*controller.PrometheusLabelRequest) ([]*controller.PrometheusLabel, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	resp := make([]*controller.PrometheusLabel, 0)
	var dbToAdd []*metadbmodel.PrometheusLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		if id, ok := l.cache.GetLabelID(n, v); ok {
			resp = append(resp, &controller.PrometheusLabel{
				Id:    proto.Uint32(uint32(id)),
				Name:  proto.String(n),
				Value: proto.String(v),
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
	l.cache.AddLabels(dbToAdd)
	for i, item := range dbToAdd {
		resp = append(resp, &controller.PrometheusLabel{
			Id:    proto.Uint32(uint32(dbToAdd[i].ID)),
			Name:  proto.String(item.Name),
			Value: proto.String(item.Value),
		})
	}
	return resp, nil
}
