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

type metricLabel struct {
	lock                  sync.Mutex
	resourceType          string
	labelEncoder          *label
	metricLabelDetailKeys mapset.Set[cache.MetricLabelDetailKey]
}

func newMetricLabel(l *label) *metricLabel {
	return &metricLabel{
		resourceType:          "metric_label",
		labelEncoder:          l,
		metricLabelDetailKeys: mapset.NewSet[cache.MetricLabelDetailKey](),
	}
}

func (ml *metricLabel) store(item *mysql.PrometheusMetricLabel) {
	if labelKey, ok := ml.labelEncoder.getKey(item.LabelID); ok {
		ml.metricLabelDetailKeys.Add(cache.NewMetricLabelDetailKey(item.MetricName, labelKey.Name, labelKey.Value))
	}
}

func (ml *metricLabel) refresh(args ...interface{}) error {
	var items []*mysql.PrometheusMetricLabel
	err := mysql.Db.Find(&items).Error
	if err != nil {
		return err
	}
	for _, item := range items {
		ml.store(item)
	}
	return nil
}

func (ml *metricLabel) encode(rMLs []*controller.PrometheusMetricLabelRequest) error {
	ml.lock.Lock()
	defer ml.lock.Unlock()

	var dbToAdd []*mysql.PrometheusMetricLabel
	for _, rML := range rMLs {
		mn := rML.GetMetricName()
		for _, l := range rML.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			if ok := ml.metricLabelDetailKeys.Contains(cache.NewMetricLabelDetailKey(mn, ln, lv)); ok {
				continue
			}
			if li, ok := ml.labelEncoder.getID(cache.NewLabelKey(ln, lv)); ok {
				dbToAdd = append(dbToAdd, &mysql.PrometheusMetricLabel{
					MetricName: mn,
					LabelID:    li,
				})
				continue
			}
			log.Warningf("%s label_id (name: %s, value: %s) not found", ml.resourceType, ln, lv)
		}
	}
	err := addBatch(dbToAdd, ml.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ml.resourceType, err.Error())
		return err
	}
	for _, item := range dbToAdd {
		ml.store(item)
	}
	return nil
}
