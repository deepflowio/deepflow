/*
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

package tagrecorder

import (
	"slices"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChAPPLabel struct {
	UpdaterComponent[metadbmodel.ChAPPLabel, PrometheusAPPLabelKey]
}

func NewChAPPLabel() *ChAPPLabel {
	updater := &ChAPPLabel{
		newUpdaterComponent[metadbmodel.ChAPPLabel, PrometheusAPPLabelKey](
			RESOURCE_TYPE_CH_APP_LABEL,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChAPPLabel) generateNewData(db *metadb.DB) (map[PrometheusAPPLabelKey]metadbmodel.ChAPPLabel, bool) {
	var prometheusLabels []metadbmodel.PrometheusLabel
	err := db.Unscoped().Find(&prometheusLabels).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	appLabelSlice, ok := l.generateAPPLabelData(db)

	labelNameIDMap, valueNameIDMap, ok := l.generateNameIDData(db)
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusAPPLabelKey]metadbmodel.ChAPPLabel)
	for _, prometheusLabel := range prometheusLabels {
		labelName := prometheusLabel.Name
		if slices.Contains(appLabelSlice, labelName) {
			labelNameID, nameOK := labelNameIDMap[labelName]
			labelValue := prometheusLabel.Value
			labelValueID, valueOK := valueNameIDMap[labelValue]
			if !nameOK || !valueOK {
				log.Warningf("label name or value not found in db, labelName: %s, labelValue: %s", labelName, labelValue)
				continue
			}
			keyToItem[PrometheusAPPLabelKey{LabelNameID: labelNameID, LabelValueID: labelValueID}] = metadbmodel.ChAPPLabel{
				LabelNameID:  labelNameID,
				LabelValue:   labelValue,
				LabelValueID: labelValueID,
			}
		}

	}
	return keyToItem, true
}

func (l *ChAPPLabel) generateKey(dbItem metadbmodel.ChAPPLabel) PrometheusAPPLabelKey {
	return PrometheusAPPLabelKey{LabelNameID: dbItem.LabelNameID, LabelValueID: dbItem.LabelValueID}
}

func (l *ChAPPLabel) generateUpdateInfo(oldItem, newItem metadbmodel.ChAPPLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.LabelValue != newItem.LabelValue {
		updateInfo["label_value"] = newItem.LabelValue
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *ChAPPLabel) generateAPPLabelData(db *metadb.DB) ([]string, bool) {
	appLabelSlice := []string{}
	var prometheusAPPMetricAPPLabelLayouts []metadbmodel.ChPrometheusMetricAPPLabelLayout
	err := db.Unscoped().Select("app_label_name").Group("app_label_name").Find(&prometheusAPPMetricAPPLabelLayouts).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return appLabelSlice, false
	}

	for _, prometheusAPPMetricAPPLabelLayout := range prometheusAPPMetricAPPLabelLayouts {
		appLabelSlice = append(appLabelSlice, prometheusAPPMetricAPPLabelLayout.APPLabelName)
	}
	return appLabelSlice, true
}

func (l *ChAPPLabel) generateNameIDData(db *metadb.DB) (map[string]int, map[string]int, bool) {
	labelNameIDMap := make(map[string]int)
	valueNameIDMap := make(map[string]int)
	var prometheusLabelNames []metadbmodel.PrometheusLabelName
	var prometheusLabelValues []metadbmodel.PrometheusLabelValue

	err := db.Unscoped().Find(&prometheusLabelNames).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, nil, false
	}

	err = db.Unscoped().Find(&prometheusLabelValues).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
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
