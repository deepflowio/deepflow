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

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type metricTarget struct {
	lock          sync.Mutex
	resourceType  string
	metricTargets mapset.Set[cache.MetricTargetKey]
}

func newMetricTarget() *metricTarget {
	return &metricTarget{
		resourceType:  "metric_target",
		metricTargets: mapset.NewSet[cache.MetricTargetKey](),
	}
}

func (mt *metricTarget) refresh(args ...interface{}) error {
	var items []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&items).Error
	if err != nil {
		return err
	}
	for _, item := range items {
		mt.metricTargets.Add(cache.NewMetricTargetKey(item.MetricName, item.TargetID))
	}
	return nil
}

func (mt *metricTarget) encode(toAdd []*controller.PrometheusMetricTarget) error {
	mt.lock.Lock()
	defer mt.lock.Unlock()

	var dbToAdd []*mysql.PrometheusMetricTarget
	for _, item := range toAdd {
		mn := item.GetMetricName()
		ti := int(item.GetTargetId())
		if ok := mt.metricTargets.Contains(cache.NewMetricTargetKey(mn, ti)); !ok {
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
		mt.metricTargets.Add(cache.NewMetricTargetKey(item.MetricName, item.TargetID))
	}
	return nil
}
