/**
 * Copyright (c) 2024 Yunshan Networks
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
	"github.com/cornelk/hashmap"
	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type metricLabel struct {
	metricNameCache *metricName
	labelCache      *label

	metricNameIDToLabelIDs *hashmap.Map[int, mapset.Set[int]]
}

func newMetricLabel(mn *metricName, l *label) *metricLabel {
	return &metricLabel{
		metricNameCache: mn,
		labelCache:      l,

		metricNameIDToLabelIDs: hashmap.New[int, mapset.Set[int]](),
	}
}

func (ml *metricLabel) IfLinked(metricID, labelID int) bool {
	if labelIDs, ok := ml.metricNameIDToLabelIDs.Get(metricID); ok {
		return labelIDs.(mapset.Set[int]).Contains(labelID)
	}
	return false
}

func (ml *metricLabel) GetLabelsByMetricName(metricName string) []int {
	mni, ok := ml.metricNameCache.GetIDByName(metricName)
	if !ok {
		log.Debugf("metric_name: %s id not found", metricName)
		return nil
	}
	if labelIDs, ok := ml.metricNameIDToLabelIDs.Get(mni); ok {
		return labelIDs.ToSlice()
	}
	log.Debugf("metric_name: %s label_ids not found", metricName)
	return []int{}
}

func (mi *metricLabel) GetMetricNameIDToLabelIDs() *hashmap.Map[int, mapset.Set[int]] {
	return mi.metricNameIDToLabelIDs
}

func (ml *metricLabel) Add(batch []*controller.PrometheusMetricLabel) {
	for _, item := range batch {
		for _, li := range item.GetLabelIds() {
			ml.metricNameIDToLabelIDs.GetOrInsert(int(item.GetMetricNameId()), mapset.NewSet[int]())
			if lids, ok := ml.metricNameIDToLabelIDs.Get(int(item.GetMetricNameId())); ok {
				lids.Add(int(li))
			}
		}
	}
}

func (ml *metricLabel) refresh(args ...interface{}) error {
	metricLabels, err := ml.load()
	if err != nil {
		return err
	}
	for _, item := range metricLabels {
		if mni, ok := ml.metricNameCache.GetIDByName(item.MetricName); ok {
			ml.metricNameIDToLabelIDs.GetOrInsert(mni, mapset.NewSet[int]())
			if lids, ok := ml.metricNameIDToLabelIDs.Get(mni); ok {
				lids.Add(item.LabelID)
			}
		}
	}
	return nil
}

func (ml *metricLabel) load() ([]*mysql.PrometheusMetricLabel, error) {
	var metricLabels []*mysql.PrometheusMetricLabel
	err := mysql.Db.Select("metric_name", "label_id").Find(&metricLabels).Error
	return metricLabels, err
}
