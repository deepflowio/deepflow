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

type MetricTargetDetailKey struct {
	MetricName string
	Instance   string
	Job        string
}

func NewMetricTargetDetailKey(metricName, instance, job string) MetricTargetDetailKey {
	return MetricTargetDetailKey{
		MetricName: metricName,
		Instance:   instance,
		Job:        job,
	}
}

type metricTarget struct {
	targetCache                  *target
	metricTargetDetailKeyMap     sync.Map       // for metric_target check
	metricNameToTargetLabelNames sync.Map       // for metric label type check
	metricNameToRandomTargetID   map[string]int // only for fully assembled
}

func newMetricTarget(tc *target) *metricTarget {
	return &metricTarget{
		targetCache:                tc,
		metricNameToRandomTargetID: make(map[string]int),
	}
}

func (t *metricTarget) GetRandomTargetID(metricName string) (int, bool) {
	id, ok := t.metricNameToRandomTargetID[metricName]
	return id, ok
}

func (t *metricTarget) GetMetricTargetDetailKey(k MetricTargetDetailKey) bool {
	_, ok := t.metricTargetDetailKeyMap.Load(k)
	return ok
}

func (t *metricTarget) GetTargetLabelNamesByMetricName(metricName string) []string {
	if labelNames, ok := t.metricNameToTargetLabelNames.Load(metricName); ok {
		return labelNames.([]string)
	}
	return []string{}
}

func (t *metricTarget) Add(batch []*controller.PrometheusMetricTarget) {
	for _, m := range batch {
		if _, ok := t.metricNameToRandomTargetID[m.GetMetricName()]; !ok {
			t.metricNameToRandomTargetID[m.GetMetricName()] = int(m.GetTargetId())
		}
		if tk, ok := t.targetCache.GetTargetKeyByTargetID(int(m.GetTargetId())); ok {
			t.metricTargetDetailKeyMap.Store(NewMetricTargetDetailKey(m.GetMetricName(), tk.Instance, tk.Job), struct{}{})
		}
	}
}

func (t *metricTarget) refresh(args ...interface{}) error {
	metricTargets, err := t.load()
	if err != nil {
		return err
	}
	metricNameToTargetLabelNames := make(map[string][]string)
	fully := args[0].(bool)
	for _, mt := range metricTargets {
		if fully {
			if _, ok := t.metricNameToRandomTargetID[mt.MetricName]; !ok {
				t.metricNameToRandomTargetID[mt.MetricName] = mt.TargetID
			}
		}
		if tKey, ok := t.targetCache.GetTargetKeyByTargetID(mt.TargetID); ok {
			t.metricTargetDetailKeyMap.Store(NewMetricTargetDetailKey(mt.MetricName, tKey.Instance, tKey.Job), struct{}{})
		}
		for k := range t.targetCache.GetTargetLabelNameToValueByTargetID(mt.TargetID) {
			metricNameToTargetLabelNames[mt.MetricName] = append(metricNameToTargetLabelNames[mt.MetricName], k)
		}
	}
	for k, v := range metricNameToTargetLabelNames {
		t.metricNameToTargetLabelNames.Store(k, v)
	}
	return nil
}

func (t *metricTarget) load() ([]*mysql.PrometheusMetricTarget, error) {
	var metricTargets []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&metricTargets).Error
	return metricTargets, err
}

func (t *metricTarget) clear() {
	t.metricNameToRandomTargetID = make(map[string]int)
}
