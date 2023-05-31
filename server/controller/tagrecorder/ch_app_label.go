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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChAPPLabel struct {
	UpdaterBase[mysql.ChAPPLabel, PrometheusAPPLabelKey]
}

func NewChAPPLabel() *ChAPPLabel {
	updater := &ChAPPLabel{
		UpdaterBase[mysql.ChAPPLabel, PrometheusAPPLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_APP_LABEL,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChAPPLabel) generateNewData() (map[PrometheusAPPLabelKey]mysql.ChAPPLabel, bool) {
	var prometheusMetricNames []mysql.PrometheusMetricName

	err := mysql.Db.Unscoped().Find(&prometheusMetricNames).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}
	metricLabelMap, ok := l.generateLayoutData()
	if !ok {
		return nil, false
	}

	labelsNameValueMap, labelsNameIDmap, ok := l.generatelabelNameValueData()
	if !ok {
		return nil, false
	}

	labelsValueIDMap, ok := l.generateLabelValueIDData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusAPPLabelKey]mysql.ChAPPLabel)
	for _, prometheusMetricName := range prometheusMetricNames {
		metricName := prometheusMetricName.Name
		labelNames := metricLabelMap[metricName]
		for _, labelName := range strings.Split(labelNames, ", ") {
			labelNameID := labelsNameIDmap[labelName]
			labelValues := labelsNameValueMap[labelName]
			for _, labelValue := range strings.Split(labelValues, ", ") {
				labelValueID := labelsValueIDMap[labelValue]
				keyToItem[PrometheusAPPLabelKey{MetricID: prometheusMetricName.ID, LabelNameID: labelNameID, LabelValueID: labelValueID}] = mysql.ChAPPLabel{
					MetricID:     prometheusMetricName.ID,
					LabelNameID:  labelNameID,
					LabelValue:   labelValue,
					LabelValueID: labelValueID,
				}
			}

		}

	}
	return keyToItem, true
}

func (l *ChAPPLabel) generateKey(dbItem mysql.ChAPPLabel) PrometheusAPPLabelKey {
	return PrometheusAPPLabelKey{MetricID: dbItem.MetricID, LabelNameID: dbItem.LabelNameID, LabelValueID: dbItem.LabelValueID}
}

func (l *ChAPPLabel) generateUpdateInfo(oldItem, newItem mysql.ChAPPLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.LabelValue != newItem.LabelValue {
		updateInfo["label_value"] = newItem.LabelValue
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *ChAPPLabel) generateLayoutData() (map[string]string, bool) {
	metricLabelMap := make(map[string]string)
	var prometheusMetricAPPLabelLayouts []mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Unscoped().Find(&prometheusMetricAPPLabelLayouts).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusMetricAPPLabelLayout := range prometheusMetricAPPLabelLayouts {
		if metricLabelMap[prometheusMetricAPPLabelLayout.MetricName] == "" {
			metricLabelMap[prometheusMetricAPPLabelLayout.MetricName] = prometheusMetricAPPLabelLayout.APPLabelName
		} else {
			metricLabelMap[prometheusMetricAPPLabelLayout.MetricName] += ", " + prometheusMetricAPPLabelLayout.APPLabelName
		}
	}
	return metricLabelMap, true
}

func (l *ChAPPLabel) generatelabelNameValueData() (map[string]string, map[string]int, bool) {
	labelsNameValueMap := make(map[string]string)
	labelsNameIDMap := make(map[string]int)
	var prometheusLabels []mysql.PrometheusLabel
	var prometheusLabelNames []mysql.PrometheusLabelName
	err := mysql.Db.Unscoped().Find(&prometheusLabels).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, false
	}

	err = mysql.Db.Unscoped().Find(&prometheusLabelNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, false
	}

	for _, prometheusLabel := range prometheusLabels {
		if labelsNameValueMap[prometheusLabel.Name] == "" {
			labelsNameValueMap[prometheusLabel.Name] = prometheusLabel.Value
		} else {
			labelsNameValueMap[prometheusLabel.Name] += ", " + prometheusLabel.Value
		}
	}
	for _, prometheusLabelName := range prometheusLabelNames {
		labelsNameIDMap[prometheusLabelName.Name] = prometheusLabelName.ID
	}
	return labelsNameValueMap, labelsNameIDMap, true
}

func (l *ChAPPLabel) generateLabelValueIDData() (map[string]int, bool) {
	metricLabelValueIDMap := make(map[string]int)
	var prometheusLabelValues []mysql.PrometheusLabelValue
	err := mysql.Db.Unscoped().Find(&prometheusLabelValues).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusLabelValue := range prometheusLabelValues {
		metricLabelValueIDMap[prometheusLabelValue.Value] = prometheusLabelValue.ID
	}
	return metricLabelValueIDMap, true
}
