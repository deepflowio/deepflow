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
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChTargetLabel struct {
	UpdaterBase[mysql.ChTargetLabel, PrometheusLabelKey]
}

func NewChTargetLabel() *ChTargetLabel {
	updater := &ChTargetLabel{
		UpdaterBase[mysql.ChTargetLabel, PrometheusLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_TARGET_LABEL,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChTargetLabel) generateNewData() (map[PrometheusLabelKey]mysql.ChTargetLabel, bool) {
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

	keyToItem := make(map[PrometheusLabelKey]mysql.ChTargetLabel)
	for _, prometheusMetricName := range prometheusMetricNames {
		metricID := prometheusMetricName.ID
		metricName := prometheusMetricName.Name
		targetIDs := strings.Split(metricNameTargetIDMap[metricName], ", ")
		for _, targetIDStr := range targetIDs {
			targetID, err := strconv.Atoi(targetIDStr)
			if err != nil {
				continue
			}
			targetLabels := strings.Split(targetLabelNameValueMap[targetID], ", ")
			for _, targetLabel := range targetLabels {
				targetLabelItem := strings.Split(targetLabel, ":")
				if len(targetLabelItem) == 2 {
					labelNameID := metricLabelNameIDMap[targetLabelItem[0]]
					labelValue := targetLabelItem[1]
					keyToItem[PrometheusLabelKey{MetricID: metricID, LabelNameID: labelNameID, LabelValue: labelValue}] = mysql.ChTargetLabel{
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

func (l *ChTargetLabel) generateKey(dbItem mysql.ChTargetLabel) PrometheusLabelKey {
	return PrometheusLabelKey{MetricID: dbItem.MetricID, LabelNameID: dbItem.LabelNameID, LabelValue: dbItem.LabelValue}
}

func (l *ChTargetLabel) generateUpdateInfo(oldItem, newItem mysql.ChTargetLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.TargetID != newItem.TargetID {
		updateInfo["target_id"] = newItem.TargetID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *ChTargetLabel) generateMetricTargetData() (map[string]string, bool) {
	metricNameTargetIDMap := make(map[string]string)
	var prometheusMetricTargets []mysql.PrometheusMetricTarget
	err := mysql.Db.Unscoped().Find(&prometheusMetricTargets).Error

	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	for _, prometheusMetricTarget := range prometheusMetricTargets {
		if metricNameTargetIDMap[prometheusMetricTarget.MetricName] == "" {
			metricNameTargetIDMap[prometheusMetricTarget.MetricName] = strconv.Itoa(prometheusMetricTarget.TargetID)
		} else {
			metricNameTargetIDMap[prometheusMetricTarget.MetricName] += ", " + strconv.Itoa(prometheusMetricTarget.TargetID)
		}

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
		targetLabelNameValueMap[prometheusTarget.ID] = "instance:" + prometheusTarget.Instance + ", job:" + prometheusTarget.Job + prometheusTarget.OtherLabels

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
