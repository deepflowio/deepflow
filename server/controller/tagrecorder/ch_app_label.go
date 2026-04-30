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
	"golang.org/x/exp/slices"

	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChAPPLabel struct {
	UpdaterComponent[mysqlmodel.ChAPPLabel, PrometheusAPPLabelKey]
}

func NewChAPPLabel() *ChAPPLabel {
	updater := &ChAPPLabel{
		newUpdaterComponent[mysqlmodel.ChAPPLabel, PrometheusAPPLabelKey](
			RESOURCE_TYPE_CH_APP_LABEL,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChAPPLabel) generateNewData(db *mysql.DB) (map[PrometheusAPPLabelKey]mysqlmodel.ChAPPLabel, bool) {
	log.Infof("generate data for %s", l.resourceTypeName, db.LogPrefixORGID)

	appLabelSlice, ok := l.generateAPPLabelData(db)

	labelNameIDMap, valueNameIDMap, ok := l.generateNameIDData(db)
	if !ok {
		return nil, false
	}

	labelRows, err := db.Unscoped().Model(&mysqlmodel.PrometheusLabel{}).Select("id", "name", "value").Rows()
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	defer labelRows.Close()

	keyToItem := make(map[PrometheusAPPLabelKey]mysqlmodel.ChAPPLabel)
	for labelRows.Next() {
		var id int
		var labelName, labelValue string
		if scanErr := labelRows.Scan(&id, &labelName, &labelValue); scanErr != nil {
			log.Errorf("stream scan %s prometheus_label interrupted: %v", l.resourceTypeName, scanErr, db.LogPrefixORGID)
			return nil, false
		}
		if slices.Contains(appLabelSlice, labelName) {
			labelNameID, nameOK := labelNameIDMap[labelName]
			labelValueID, valueOK := valueNameIDMap[labelValue]
			if !nameOK || !valueOK {
				log.Warningf("label name or value not found in db, labelName: %s, labelValue: %s", labelName, labelValue)
				continue
			}
			keyToItem[PrometheusAPPLabelKey{LabelNameID: labelNameID, LabelValueID: labelValueID}] = mysqlmodel.ChAPPLabel{
				LabelNameID:  labelNameID,
				LabelValue:   labelValue,
				LabelValueID: labelValueID,
			}
		}
	}
	if err := labelRows.Err(); err != nil {
		log.Errorf("stream read %s prometheus_label error: %v", l.resourceTypeName, err, db.LogPrefixORGID)
		return nil, false
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

func (l *ChAPPLabel) generateAPPLabelData(db *mysql.DB) ([]string, bool) {
	appLabelSlice := []string{}
	var prometheusAPPMetricAPPLabelLayouts []mysqlmodel.ChPrometheusMetricAPPLabelLayout
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

func (l *ChAPPLabel) generateNameIDData(db *mysql.DB) (map[string]int, map[string]int, bool) {
	labelNameIDMap := make(map[string]int)
	valueNameIDMap := make(map[string]int)

	nameRows, err := db.Unscoped().Model(&mysqlmodel.PrometheusLabelName{}).Select("id", "name").Rows()
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, nil, false
	}
	defer nameRows.Close()
	for nameRows.Next() {
		var id int
		var name string
		if scanErr := nameRows.Scan(&id, &name); scanErr != nil {
			log.Errorf("stream scan %s prometheus_label_name interrupted: %v", l.resourceTypeName, scanErr, db.LogPrefixORGID)
			return nil, nil, false
		}
		labelNameIDMap[name] = id
	}
	if err := nameRows.Err(); err != nil {
		log.Errorf("stream read %s prometheus_label_name error: %v", l.resourceTypeName, err, db.LogPrefixORGID)
		return nil, nil, false
	}

	valueRows, err := db.Unscoped().Model(&mysqlmodel.PrometheusLabelValue{}).Select("id", "value").Rows()
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, nil, false
	}
	defer valueRows.Close()
	for valueRows.Next() {
		var id int
		var value string
		if scanErr := valueRows.Scan(&id, &value); scanErr != nil {
			log.Errorf("stream scan %s prometheus_label_value interrupted: %v", l.resourceTypeName, scanErr, db.LogPrefixORGID)
			return nil, nil, false
		}
		valueNameIDMap[value] = id
	}
	if err := valueRows.Err(); err != nil {
		log.Errorf("stream read %s prometheus_label_value error: %v", l.resourceTypeName, err, db.LogPrefixORGID)
		return nil, nil, false
	}
	return labelNameIDMap, valueNameIDMap, true
}
