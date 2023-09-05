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
	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type MetricLabelDetailKey struct {
	MetricName string
	LabelName  string
	LabelValue string
}

func NewMetricLabelDetailKey(metricName, labelName, labelValue string) MetricLabelDetailKey {
	return MetricLabelDetailKey{
		MetricName: metricName,
		LabelName:  labelName,
		LabelValue: labelValue,
	}
}

type metricLabel struct {
	labelCache            *label
	metricLabelDetailKeys mapset.Set[MetricLabelDetailKey] // for metric_label check
	metricNameToLabelIDs  map[string][]int                 // only for fully assembled
}

func newMetricLabel(l *label) *metricLabel {
	return &metricLabel{
		labelCache:            l,
		metricLabelDetailKeys: mapset.NewSet[MetricLabelDetailKey](),
		metricNameToLabelIDs:  make(map[string][]int),
	}
}

func (ml *metricLabel) IfKeyExists(k MetricLabelDetailKey) bool {
	return ml.metricLabelDetailKeys.Contains(k)
}

func (ml *metricLabel) GetLabelsByMetricName(metricName string) []LabelKey {
	var ret []LabelKey
	if labelIDs, ok := ml.metricNameToLabelIDs[metricName]; ok {
		for _, labelID := range labelIDs {
			if labelKey, ok := ml.labelCache.GetKeyByID(labelID); ok {
				ret = append(ret, labelKey)
			}
		}
	}
	return ret
}

func (ml *metricLabel) Add(batch []MetricLabelDetailKey) {
	for _, item := range batch {
		ml.metricLabelDetailKeys.Add(item)
	}
}

func (ml *metricLabel) GetMetricLabelDetailKeys() mapset.Set[MetricLabelDetailKey] {
	return ml.metricLabelDetailKeys
}

func (ml *metricLabel) refresh(args ...interface{}) error {
	metricLabels, err := ml.load()
	if err != nil {
		return err
	}
	metricNameToLabelIDs := make(map[string][]int)
	for _, item := range metricLabels {
		if lk, ok := ml.labelCache.GetKeyByID(item.LabelID); ok {
			ml.metricLabelDetailKeys.Add(NewMetricLabelDetailKey(item.MetricName, lk.Name, lk.Value))
		}
		if _, ok := ml.labelCache.GetKeyByID(item.LabelID); ok {
			metricNameToLabelIDs[item.MetricName] = append(metricNameToLabelIDs[item.MetricName], item.LabelID)
		}
	}
	ml.metricNameToLabelIDs = metricNameToLabelIDs
	return nil
}

func (ml *metricLabel) load() ([]*mysql.PrometheusMetricLabel, error) {
	var metricLabels []*mysql.PrometheusMetricLabel
	err := mysql.Db.Find(&metricLabels).Error
	return metricLabels, err
}
