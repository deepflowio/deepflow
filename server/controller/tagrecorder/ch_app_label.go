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
	promcache "github.com/deepflowio/deepflow/server/controller/prometheus/cache"
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
	log.Infof("generate data for %s", l.resourceTypeName, db.LogPrefixORGID)

	appLabelSlice, ok := l.generateAPPLabelData(db)
	if !ok {
		return nil, false
	}

	promCache, err := promcache.GetCache(db.ORGID)
	if err != nil {
		log.Errorf("get prometheus cache failed: %v", err)
		return nil, false
	}
	promCache.Refresh(true)

	labelRows, err := db.Unscoped().Model(&metadbmodel.PrometheusLabel{}).Select("name", "value").Rows()
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	defer labelRows.Close()

	keyToItem := make(map[PrometheusAPPLabelKey]metadbmodel.ChAPPLabel)
	for labelRows.Next() {
		var labelName, labelValue string
		if scanErr := labelRows.Scan(&labelName, &labelValue); scanErr != nil {
			log.Errorf("stream scan %s prometheus_label interrupted: %v", l.resourceTypeName, scanErr, db.LogPrefixORGID)
			return nil, false
		}
		if slices.Contains(appLabelSlice, labelName) {
			labelNameID, nameOK := promCache.GetLabelNameID(labelName)
			labelValueID, valueOK := promCache.GetLabelValueID(labelValue)
			if !nameOK || !valueOK {
				log.Warningf("label name or value not found in cache, labelName: %s, labelValue: %s", labelName, labelValue)
				continue
			}
			keyToItem[PrometheusAPPLabelKey{LabelNameID: labelNameID, LabelValueID: labelValueID}] = metadbmodel.ChAPPLabel{
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
