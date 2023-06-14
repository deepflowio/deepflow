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

type metricLabel struct {
	resourceType          string
	label                 *label
	metricLabelDetailKeys sync.Map
}

func newMetricLabel(l *label) *metricLabel {
	return &metricLabel{
		resourceType: "metric_label",
		label:        l,
	}
}

func (ml *metricLabel) store(item *mysql.PrometheusMetricLabel) {
	if labelKey, ok := ml.label.getKey(item.LabelID); ok {
		ml.metricLabelDetailKeys.Store(cache.NewMetricLabelDetailKey(item.MetricName, labelKey.Name, labelKey.Value), item.LabelID)
	}
}

func (ml *metricLabel) refresh(args ...interface{}) error {
	var ls []*mysql.PrometheusMetricLabel
	err := mysql.Db.Find(&ls).Error
	if err != nil {
		return err
	}
	for _, item := range ls {
		ml.store(item)
	}
	return nil
}

func (ml *metricLabel) encode(rMLs []*controller.PrometheusMetricLabelRequest) error {
	var dbToAdd []*mysql.PrometheusMetricLabel
	for _, rML := range rMLs {
		mn := rML.GetMetricName()
		for _, l := range rML.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			if li, ok := ml.label.getID(cache.NewLabelKey(ln, lv)); ok {
				dbToAdd = append(dbToAdd, &mysql.PrometheusMetricLabel{
					MetricName: mn,
					LabelID:    li,
				})
			}
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
