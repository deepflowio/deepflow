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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type ChAPPLabel struct {
	UpdaterBase[mysqlmodel.ChAPPLabel, PrometheusAPPLabelKey]
}

func NewChAPPLabel() *ChAPPLabel {
	updater := &ChAPPLabel{
		UpdaterBase[mysqlmodel.ChAPPLabel, PrometheusAPPLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_APP_LABEL,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChAPPLabel) generateNewData() (map[PrometheusAPPLabelKey]mysqlmodel.ChAPPLabel, bool) {
	var prometheusLabels []mysqlmodel.PrometheusLabel
	err := mysql.DefaultDB.Unscoped().Find(&prometheusLabels).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	appLabelSlice, ok := l.generateAPPLabelData()

	labelNameIDMap, valueNameIDMap, ok := l.generateNameIDData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusAPPLabelKey]mysqlmodel.ChAPPLabel)
	for _, prometheusLabel := range prometheusLabels {
		labelName := prometheusLabel.Name
		if slices.Contains(appLabelSlice, labelName) {
			labelNameID := labelNameIDMap[labelName]
			labelValue := prometheusLabel.Value
			labelValueID := valueNameIDMap[labelValue]
			keyToItem[PrometheusAPPLabelKey{LabelNameID: labelNameID, LabelValueID: labelValueID}] = mysqlmodel.ChAPPLabel{
				LabelNameID:  labelNameID,
				LabelValue:   labelValue,
				LabelValueID: labelValueID,
			}
		}

	}
	return keyToItem, true
}

func (l *ChAPPLabel) generateKey(dbItem mysqlmodel.ChAPPLabel) PrometheusAPPLabelKey {
	return PrometheusAPPLabelKey{LabelNameID: dbItem.LabelNameID, LabelValueID: dbItem.LabelValueID}
}

func (l *ChAPPLabel) generateUpdateInfo(oldItem, newItem mysqlmodel.ChAPPLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.LabelValue != newItem.LabelValue {
		updateInfo["label_value"] = newItem.LabelValue
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *ChAPPLabel) generateAPPLabelData() ([]string, bool) {
	appLabelSlice := []string{}
	var prometheusAPPMetricAPPLabelLayouts []mysqlmodel.ChPrometheusMetricAPPLabelLayout
	err := mysql.DefaultDB.Unscoped().Select("app_label_name").Group("app_label_name").Find(&prometheusAPPMetricAPPLabelLayouts).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return appLabelSlice, false
	}

	for _, prometheusAPPMetricAPPLabelLayout := range prometheusAPPMetricAPPLabelLayouts {
		appLabelSlice = append(appLabelSlice, prometheusAPPMetricAPPLabelLayout.APPLabelName)
	}
	return appLabelSlice, true
}

func (l *ChAPPLabel) generateNameIDData() (map[string]int, map[string]int, bool) {
	labelNameIDMap := make(map[string]int)
	valueNameIDMap := make(map[string]int)
	var prometheusLabelNames []mysqlmodel.PrometheusLabelName
	var prometheusLabelValues []mysqlmodel.PrometheusLabelValue

	err := mysql.DefaultDB.Unscoped().Find(&prometheusLabelNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, false
	}

	err = mysql.DefaultDB.Unscoped().Find(&prometheusLabelValues).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, nil, false
	}

	for _, prometheusLabelName := range prometheusLabelNames {
		labelNameIDMap[prometheusLabelName.Name] = prometheusLabelName.ID
	}

	for _, prometheusLabelValue := range prometheusLabelValues {
		valueNameIDMap[prometheusLabelValue.Value] = prometheusLabelValue.ID
	}
	return labelNameIDMap, valueNameIDMap, true
}
