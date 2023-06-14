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
	"golang.org/x/exp/slices"

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
	var prometheusMetricLabels []mysql.PrometheusMetricLabel

	err := mysql.Db.Unscoped().Find(&prometheusMetricLabels).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}
	metricLabelIDNameValueMap, ok := l.generateLabelIDNameValueData()
	if !ok {
		return nil, false
	}

	metricNameIDMap, labelNameIDMap, valueNameIDMap, ok := l.generateNameIDData()
	if !ok {
		return nil, false
	}

	metricNameMap, ok := l.generateMerticNameData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusAPPLabelKey]mysql.ChAPPLabel)
	for _, prometheusMetricLabel := range prometheusMetricLabels {
		metricName := prometheusMetricLabel.MetricName
		if len(metricNameMap[metricName]) > 0 {

			metricNameData := metricNameMap[metricName]
			metricID := metricNameIDMap[metricName]
			labelID := prometheusMetricLabel.LabelID
			labelNameValueData := metricLabelIDNameValueMap[labelID]
			labelName := labelNameValueData["label_name"]
			indexOK := slices.Contains[string](metricNameData, labelName)

			if indexOK {
				labelNameID := labelNameIDMap[labelName]
				labelValue := labelNameValueData["label_value"]
				labelValueID := valueNameIDMap[labelValue]
				keyToItem[PrometheusAPPLabelKey{MetricID: metricID, LabelNameID: labelNameID, LabelValueID: labelValueID}] = mysql.ChAPPLabel{
					MetricID:     metricID,
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

func (l *ChAPPLabel) generateMerticNameData() (map[string][]string, bool) {
	metricNameMap := make(map[string][]string)
	var prometheusMetricAPPLabelLayouts []mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Unscoped().Find(&prometheusMetricAPPLabelLayouts).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusMetricAPPLabelLayout := range prometheusMetricAPPLabelLayouts {
		metricNameMap[prometheusMetricAPPLabelLayout.MetricName] = append(metricNameMap[prometheusMetricAPPLabelLayout.MetricName], prometheusMetricAPPLabelLayout.APPLabelName)
	}
	return metricNameMap, true
}

func (l *ChAPPLabel) generateLabelIDNameValueData() (map[int]map[string]string, bool) {
	metricLabelIDNameValueMap := make(map[int]map[string]string)
	var prometheusLabels []mysql.PrometheusLabel
	err := mysql.Db.Unscoped().Find(&prometheusLabels).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusLabel := range prometheusLabels {
		metricLabelIDNameValueMap[prometheusLabel.ID] = map[string]string{"label_name": prometheusLabel.Name, "label_value": prometheusLabel.Value}
	}
	return metricLabelIDNameValueMap, true
}

func (l *ChAPPLabel) generateNameIDData() (map[string]int, map[string]int, map[string]int, bool) {
	metricNameIDMap := make(map[string]int)
	labelNameIDMap := make(map[string]int)
	valueNameIDMap := make(map[string]int)
	var prometheusMetricNames []mysql.PrometheusMetricName
	var prometheusLabelNames []mysql.PrometheusLabelName
	var prometheusLabelValues []mysql.PrometheusLabelValue

	err := mysql.Db.Unscoped().Find(&prometheusMetricNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, nil, false
	}

	err = mysql.Db.Unscoped().Find(&prometheusLabelNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, nil, false
	}

	err = mysql.Db.Unscoped().Find(&prometheusLabelValues).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, nil, false
	}

	for _, prometheusMetricName := range prometheusMetricNames {
		metricNameIDMap[prometheusMetricName.Name] = prometheusMetricName.ID
	}

	for _, prometheusLabelName := range prometheusLabelNames {
		labelNameIDMap[prometheusLabelName.Name] = prometheusLabelName.ID
	}

	for _, prometheusLabelValue := range prometheusLabelValues {
		valueNameIDMap[prometheusLabelValue.Value] = prometheusLabelValue.ID
	}
	return metricNameIDMap, labelNameIDMap, valueNameIDMap, true
}
