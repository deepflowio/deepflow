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

func (l *ChTargetLabel) generateNewData() (map[PrometheusTargetLabelKey]mysql.ChTargetLabel, bool) {

	targetLabelNameValueMap, ok := l.generateTargetData()
	if !ok {
		return nil, false
	}

	metricLabelNameIDMap, ok := l.generateLabelNameIDData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[PrometheusTargetLabelKey]mysql.ChTargetLabel)
	for targetID, targetLabels := range targetLabelNameValueMap {
		targetLabelSlice := strings.Split(targetLabels, ", ")
		for _, targetLabel := range targetLabelSlice {
			if len(strings.Split(targetLabel, ":")) >= 2 {
				targetLabelItem := strings.SplitN(targetLabel, ":", 2)
				labelNameID := metricLabelNameIDMap[targetLabelItem[0]]
				labelValue := targetLabelItem[1]
				keyToItem[PrometheusTargetLabelKey{LabelNameID: labelNameID, TargetID: targetID}] = mysql.ChTargetLabel{
					LabelNameID: labelNameID,
					LabelValue:  labelValue,
					TargetID:    targetID,
				}
			}
		}
	}
	return keyToItem, true
}

func (l *ChTargetLabel) generateKey(dbItem mysql.ChTargetLabel) PrometheusTargetLabelKey {
	return PrometheusTargetLabelKey{LabelNameID: dbItem.LabelNameID, TargetID: dbItem.TargetID}
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
