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
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type label struct {
	lock         sync.Mutex
	resourceType string
	labelKeyToID sync.Map
	labelIDToKey sync.Map
}

func newLabel() *label {
	return &label{
		resourceType: "label",
	}
}

func (l *label) store(item *mysql.PrometheusLabel) {
	l.labelKeyToID.Store(cache.NewLabelKey(item.Name, item.Value), item.ID)
	l.labelIDToKey.Store(item.ID, cache.NewLabelKey(item.Name, item.Value))
}

func (l *label) getKey(id int) (cache.LabelKey, bool) {
	if item, ok := l.labelIDToKey.Load(id); ok {
		return item.(cache.LabelKey), true
	}
	return cache.LabelKey{}, false
}

func (l *label) getID(key cache.LabelKey) (int, bool) {
	if item, ok := l.labelKeyToID.Load(key); ok {
		return item.(int), true
	}
	return 0, false
}

func (l *label) refresh(args ...interface{}) error {
	log.Infof("refresh %s", l.resourceType)
	var items []*mysql.PrometheusLabel
	err := mysql.Db.Find(&items).Error
	if err != nil {
		return err
	}
	for _, item := range items {
		l.store(item)
	}
	return nil
}

func (l *label) encode(toAdd []*controller.PrometheusLabelRequest) ([]*controller.PrometheusLabel, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	resp := make([]*controller.PrometheusLabel, 0)
	var dbToAdd []*mysql.PrometheusLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		if id, ok := l.getID(cache.NewLabelKey(n, v)); ok {
			resp = append(resp, &controller.PrometheusLabel{
				Name:  &n,
				Value: &v,
				Id:    proto.Uint32(uint32(id)),
			})
			continue
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusLabel{
			Name:  n,
			Value: v,
		})
	}

	err := addBatch(dbToAdd, l.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", l.resourceType, err.Error())
		return nil, err
	}
	for _, item := range dbToAdd {
		l.store(item)
		resp = append(resp, &controller.PrometheusLabel{
			Name:  &item.Name,
			Value: &item.Value,
			Id:    proto.Uint32(uint32(item.ID)),
		})

	}
	return resp, nil
}
