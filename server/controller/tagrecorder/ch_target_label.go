/*
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

package tagrecorder

import (
	"sort"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChTargetLabel struct {
	UpdaterBase[mysql.ChTargetLabel, PrometheusTargetLabelKey]
}

func NewChTargetLabel() *ChTargetLabel {
	updater := &ChTargetLabel{
		UpdaterBase[mysql.ChTargetLabel, PrometheusTargetLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_TARGET_LABEL,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChTargetLabel) getNewData() ([]mysql.ChTargetLabel, bool) {
	keyToItem, ok := l.generateNewData()
	if !ok {
		return nil, false
	}

	items := make([]mysql.ChTargetLabel, len(keyToItem))
	i := 0
	for _, data := range keyToItem {
		items[i] = data
		i++
	}
	sort.SliceIsSorted(items, func(i, j int) bool {
		return items[i].MetricID < items[j].MetricID
	})
	sort.SliceIsSorted(items, func(i, j int) bool {
		return items[i].LabelNameID < items[j].LabelNameID
	})
	sort.SliceIsSorted(items, func(i, j int) bool {
		return items[i].TargetID < items[j].TargetID
	})
	return items, true
}

func (l *ChTargetLabel) generateNewData() (map[PrometheusTargetLabelKey]mysql.ChTargetLabel, bool) {
	var prometheusMetricNames []mysql.PrometheusMetricName

	err := mysql.Db.Unscoped().Find(&prometheusMetricNames).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	metricNameTargetIDMap, ok := l.generateMetricTargetData()
	if !ok {
		return nil, false
	}

	targetLabelNameValueMap, ok := l.generateTargetData()
	if !ok {
		return nil, false
	}

	metricLabelNameIDMap, ok := l.generateLabelNameIDData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusTargetLabelKey]mysql.ChTargetLabel)
	for _, prometheusMetricName := range prometheusMetricNames {
		metricID := prometheusMetricName.ID
		metricName := prometheusMetricName.Name
		targetIDs := metricNameTargetIDMap[metricName]
		for _, targetID := range targetIDs {
			targetLabels := strings.Split(targetLabelNameValueMap[targetID], ", ")
			for _, targetLabel := range targetLabels {
				if len(strings.Split(targetLabel, ":")) >= 2 {
					targetLabelItem := strings.SplitN(targetLabel, ":", 2)
					labelNameID := metricLabelNameIDMap[targetLabelItem[0]]
					labelValue := targetLabelItem[1]
					keyToItem[PrometheusTargetLabelKey{MetricID: metricID, LabelNameID: labelNameID, TargetID: targetID}] = mysql.ChTargetLabel{
						MetricID:    metricID,
						LabelNameID: labelNameID,
						LabelValue:  labelValue,
						TargetID:    targetID,
					}
				}
			}
		}
	}
	return keyToItem, true
}

func (l *ChTargetLabel) generateKey(dbItem mysql.ChTargetLabel) PrometheusTargetLabelKey {
	return PrometheusTargetLabelKey{MetricID: dbItem.MetricID, LabelNameID: dbItem.LabelNameID, TargetID: dbItem.TargetID}
}

func (l *ChTargetLabel) generateUpdateInfo(oldItem, newItem mysql.ChTargetLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.LabelValue != newItem.LabelValue {
		updateInfo["label_value"] = newItem.LabelValue
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *ChTargetLabel) generateMetricTargetData() (map[string][]int, bool) {
	metricNameTargetIDMap := make(map[string][]int)
	var prometheusMetricTargets []mysql.PrometheusMetricTarget
	err := mysql.Db.Unscoped().Find(&prometheusMetricTargets).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusMetricTarget := range prometheusMetricTargets {
		metricNameTargetIDMap[prometheusMetricTarget.MetricName] = append(metricNameTargetIDMap[prometheusMetricTarget.MetricName], prometheusMetricTarget.TargetID)
	}

	return metricNameTargetIDMap, true
}

func (l *ChTargetLabel) generateTargetData() (map[int]string, bool) {
	targetLabelNameValueMap := make(map[int]string)
	var prometheusTargets []mysql.PrometheusTarget
	err := mysql.Db.Unscoped().Find(&prometheusTargets).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusTarget := range prometheusTargets {
		targetLabelNameValueMap[prometheusTarget.ID] = "instance:" + prometheusTarget.Instance + ", job:" + prometheusTarget.Job + ", " + prometheusTarget.OtherLabels

	}

	return targetLabelNameValueMap, true
}

func (l *ChTargetLabel) generateLabelNameIDData() (map[string]int, bool) {
	metricLabelNameIDMap := make(map[string]int)
	var prometheusLabelNames []mysql.PrometheusLabelName
	err := mysql.Db.Unscoped().Find(&prometheusLabelNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusLabelName := range prometheusLabelNames {
		metricLabelNameIDMap[prometheusLabelName.Name] = prometheusLabelName.ID
	}

	return metricLabelNameIDMap, true
}
