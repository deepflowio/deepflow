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

package synchronizer

import (
	"sync"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/side/prometheus/cache"
)

type label struct {
	mux          sync.Mutex
	resourceType string
	labels       map[cache.LabelKey]struct{}
}

func newLabel() *label {
	return &label{
		resourceType: "label",
		labels:       make(map[cache.LabelKey]struct{}),
	}
}

func (l *label) refresh(args ...interface{}) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	var ls []*mysql.PrometheusLabel
	err := mysql.Db.Find(&ls).Error
	if err != nil {
		return err
	}
	for _, item := range ls {
		l.labels[cache.NewLabelKey(item.Name, item.Value)] = struct{}{}
	}
	return nil
}

func (l *label) sync(toAdd []*controller.PrometheusLabel) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	var dbToAdd []*mysql.PrometheusLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		if _, ok := l.labels[cache.NewLabelKey(n, v)]; !ok {
			dbToAdd = append(dbToAdd, &mysql.PrometheusLabel{
				Name:  n,
				Value: v,
			})
		}
	}

	err := l.addBatch(dbToAdd)
	if err != nil {
		log.Errorf("add %s error: %s", l.resourceType, err.Error())
		return err
	}
	for _, item := range dbToAdd {
		l.labels[cache.NewLabelKey(item.Name, item.Value)] = struct{}{}
	}
	return nil
}

func (l *label) addBatch(toAdd []*mysql.PrometheusLabel) error {
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		oneP := toAdd[start:end]
		err := mysql.Db.Create(&oneP).Error
		if err != nil {
			return err
		}
		log.Infof("add %d %s success", len(oneP), l.resourceType)
	}
	return nil
}
