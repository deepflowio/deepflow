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

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type metricTarget struct {
	mux           sync.Mutex
	resourceType  string
	metricTargets map[cache.MetricTargetKey]struct{}
}

func newMetricTarget() *metricTarget {
	return &metricTarget{
		resourceType:  "metric_target",
		metricTargets: make(map[cache.MetricTargetKey]struct{}),
	}
}

func (mt *metricTarget) refresh(args ...interface{}) error {
	mt.mux.Lock()
	defer mt.mux.Unlock()

	var ls []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&ls).Error
	if err != nil {
		return err
	}
	for _, item := range ls {
		mt.metricTargets[cache.NewMetricTargetKey(item.MetricName, item.TargetID)] = struct{}{}
	}
	return nil
}

func (mt *metricTarget) sync(toAdd []*controller.PrometheusMetricTarget) error {
	mt.mux.Lock()
	defer mt.mux.Unlock()

	var dbToAdd []*mysql.PrometheusMetricTarget
	for _, item := range toAdd {
		mn := item.GetMetricName()
		ti := int(item.GetTargetId())
		if _, ok := mt.metricTargets[cache.NewMetricTargetKey(mn, ti)]; !ok {
			dbToAdd = append(dbToAdd, &mysql.PrometheusMetricTarget{
				MetricName: mn,
				TargetID:   ti,
			})
		}
	}
	err := addBatch(dbToAdd, mt.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", mt.resourceType, err.Error())
		return err
	}
	for _, item := range dbToAdd {
		mt.metricTargets[cache.NewMetricTargetKey(item.MetricName, item.TargetID)] = struct{}{}
	}
	return nil
}
