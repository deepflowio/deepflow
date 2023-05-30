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
)

type metricTarget struct {
	mux                  sync.Mutex
	resourceType         string
	metricNameToTargetID map[string]int
}

func newMetricTarget() *metricTarget {
	return &metricTarget{
		resourceType:         "metric_target",
		metricNameToTargetID: make(map[string]int),
	}
}

func (l *metricTarget) refresh(args ...interface{}) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	var ls []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&ls).Error
	if err != nil {
		return err
	}
	for i := range ls {
		l.metricNameToTargetID[ls[i].MetricName] = ls[i].TargetID
	}
	return nil
}

func (l *metricTarget) sync(toAdd []*controller.PrometheusMetricTarget) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	var dbToAdd []*mysql.PrometheusMetricTarget
	for i := range toAdd {
		mn := toAdd[i].GetMetricName()
		if _, ok := l.metricNameToTargetID[mn]; !ok {
			dbToAdd = append(dbToAdd, &mysql.PrometheusMetricTarget{
				MetricName: mn,
				TargetID:   int(toAdd[i].GetTargetId()),
			})
		}
	}
	err := l.addBatch(dbToAdd)
	if err != nil {
		return err
	}
	for i := range dbToAdd {
		l.metricNameToTargetID[dbToAdd[i].MetricName] = dbToAdd[i].TargetID
	}
	return nil
}

func (l *metricTarget) addBatch(toAdd []*mysql.PrometheusMetricTarget) error {
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
