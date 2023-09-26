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

type metricLabelKey struct {
	MetricNameID int
	LabelID      int
}

func newMetricLabelKey(metricNameID, labelID int) metricLabelKey {
	return metricLabelKey{
		MetricNameID: metricNameID,
		LabelID:      labelID,
	}
}

type metricLabel struct {
	lock         sync.Mutex
	resourceType string

	metricNameEncoder *metricName
	labelEncoder      *label

	metricLabelKeys mapset.Set[metricLabelKey]
}

func newMetricLabel(mn *metricName, l *label) *metricLabel {
	return &metricLabel{
		resourceType:      "metric_label",
		metricNameEncoder: mn,
		labelEncoder:      l,
		metricLabelKeys:   mapset.NewSet[metricLabelKey](),
	}
}

func (ml *metricLabel) store(item *mysql.PrometheusMetricLabel) {
	if mni, ok := ml.metricNameEncoder.getID(item.MetricName); ok {
		ml.metricLabelKeys.Add(newMetricLabelKey(mni, item.LabelID))
	}
}

func (ml *metricLabel) refresh(args ...interface{}) error {
	var items []*mysql.PrometheusMetricLabel
	err := mysql.Db.Select("metric_name", "label_id").Find(&items).Error
	if err != nil {
		return err
	}
	for _, item := range items {
		ml.store(item)
	}
	return nil
}

func (ml *metricLabel) encode(rMLs []*controller.PrometheusMetricLabelRequest) ([]*controller.PrometheusMetricLabel, error) {
	ml.lock.Lock()
	defer ml.lock.Unlock()

	resp := make([]*controller.PrometheusMetricLabel, 0)
	var dbToAdd []*mysql.PrometheusMetricLabel
	respToAdd := make([]*controller.PrometheusMetricLabel, 0)
	for _, rML := range rMLs {
		mn := rML.GetMetricName()
		mni, ok := ml.metricNameEncoder.getID(mn)
		if !ok {
			log.Warningf("%s metric_name: %s id not found", ml.resourceType, mn)
			continue
		}
		lis := make([]uint32, 0)
		lisToAdd := make([]uint32, 0)
		for _, l := range rML.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			li, ok := ml.labelEncoder.getID(cache.NewLabelKey(ln, lv))
			if !ok {
				log.Warningf("%s label (name: %s, value: %s) id not found", ml.resourceType, ln, lv)
				continue
			}
			if ok := ml.metricLabelKeys.Contains(newMetricLabelKey(mni, li)); ok {
				lis = append(lis, uint32(li))
				continue
			}
			dbToAdd = append(dbToAdd, &mysql.PrometheusMetricLabel{
				MetricName: mn,
				LabelID:    li,
			})
			lisToAdd = append(lisToAdd, uint32(li))
		}
		if len(lis) != 0 {
			resp = append(resp, &controller.PrometheusMetricLabel{
				MetricNameId: proto.Uint32(uint32(mni)),
				LabelIds:     lis,
			})
		}
		if len(lisToAdd) != 0 {
			respToAdd = append(respToAdd, &controller.PrometheusMetricLabel{
				MetricNameId: proto.Uint32(uint32(mni)),
				LabelIds:     lisToAdd,
			})
		}
	}
	err := addBatch(dbToAdd, ml.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ml.resourceType, err.Error())
		return resp, err
	}
	for _, item := range dbToAdd {
		ml.store(item)
	}
	return append(resp, respToAdd...), nil
}
