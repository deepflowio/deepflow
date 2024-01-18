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
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type metricTarget struct {
	lock          sync.Mutex
	resourceType  string
	metricTargets mapset.Set[cache.MetricTargetKey]
	targetEncoder *target
}

func newMetricTarget(te *target) *metricTarget {
	return &metricTarget{
		resourceType:  "metric_target",
		metricTargets: mapset.NewSet[cache.MetricTargetKey](),
		targetEncoder: te,
	}
}

func (mt *metricTarget) refresh() error {
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

func (mt *metricTarget) encode(toAdd []*controller.PrometheusMetricTargetRequest) ([]*controller.PrometheusMetricTarget, error) {
	mt.lock.Lock()
	defer mt.lock.Unlock()

	resp := make([]*controller.PrometheusMetricTarget, 0)
	var dbToAdd []*mysql.PrometheusMetricTarget
	for _, item := range toAdd {
		mn := item.GetMetricName()
		ti := int(item.GetTargetId())
		if ti == 0 {
			ti, _ = mt.targetEncoder.getID(cache.NewTargetKey(item.GetInstance(), item.GetJob(), int(item.GetEpcId()), int(item.GetPodClusterId())))
		}
		if ti != 0 {
			if ok := mt.metricTargets.Contains(cache.NewMetricTargetKey(mn, ti)); ok {
				resp = append(resp, &controller.PrometheusMetricTarget{
					MetricName: &mn,
					TargetId:   proto.Uint32(uint32(ti)),
				})
				continue
			}
			dbToAdd = append(dbToAdd, &mysql.PrometheusMetricTarget{
				MetricName: mn,
				TargetID:   ti,
			})
		}
	}

	err := addBatch(dbToAdd, mt.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", mt.resourceType, err.Error())
		return resp, err
	}
	for _, item := range dbToAdd {
		mt.metricTargets.Add(cache.NewMetricTargetKey(item.MetricName, item.TargetID))
		resp = append(resp, &controller.PrometheusMetricTarget{
			MetricName: &item.MetricName,
			TargetId:   proto.Uint32(uint32(item.TargetID)),
		})
	}
	return resp, nil
}
