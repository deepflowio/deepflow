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

package cache

import (
	"sync"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type MetricTargetKey struct {
	MetricName string
	TargetID   int
}

func NewMetricTargetKey(metricName string, targetID int) MetricTargetKey {
	return MetricTargetKey{
		MetricName: metricName,
		TargetID:   targetID,
	}
}

type metricTarget struct {
	metricNameToTargetID sync.Map
}

func (t *metricTarget) GetTargetIDByMetricName(metricName string) (int, bool) {
	if id, ok := t.metricNameToTargetID.Load(metricName); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *metricTarget) Add(batch []*controller.PrometheusMetricTarget) {
	for _, m := range batch {
		t.metricNameToTargetID.Store(m.GetMetricName(), int(m.GetTargetId()))
	}
}

func (t *metricTarget) refresh(args ...interface{}) error {
	metricTargets, err := t.load()
	if err != nil {
		return err
	}
	for _, mt := range metricTargets {
		t.metricNameToTargetID.Store(mt.MetricName, mt.TargetID)
	}
	return nil
}

func (t *metricTarget) load() ([]*mysql.PrometheusMetricTarget, error) {
	var metricTargets []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&metricTargets).Error
	return metricTargets, err
}
