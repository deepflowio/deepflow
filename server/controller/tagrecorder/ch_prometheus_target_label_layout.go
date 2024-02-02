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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPrometheusTargetLabelLayout struct {
	UpdaterComponent[mysql.ChPrometheusTargetLabelLayout, IDKey]
}

func NewChPrometheusTargetLabelLayout() *ChPrometheusTargetLabelLayout {
	updater := &ChPrometheusTargetLabelLayout{
		newUpdaterComponent[mysql.ChPrometheusTargetLabelLayout, IDKey](
			RESOURCE_TYPE_CH_PROMETHEUS_TARGET_LABEL_LAYOUT,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChPrometheusTargetLabelLayout) generateNewData() (map[IDKey]mysql.ChPrometheusTargetLabelLayout, bool) {
	var prometheusTargets []mysql.PrometheusTarget

	err := mysql.Db.Unscoped().Find(&prometheusTargets).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPrometheusTargetLabelLayout)
	for _, prometheusTarget := range prometheusTargets {
		targetLabelNames := "job, instance"
		targetLabelValues := prometheusTarget.Job + ", " + prometheusTarget.Instance
		otherLabels := strings.Split(prometheusTarget.OtherLabels, ", ")
		if len(otherLabels) > 0 {
			for _, otherLabel := range otherLabels {
				if len(strings.Split(otherLabel, ":")) >= 2 {
					otherLabelItem := strings.SplitN(otherLabel, ":", 2)
					targetLabelNames += ", " + otherLabelItem[0]
					targetLabelValues += ", " + otherLabelItem[1]
				}
			}
		}
		keyToItem[IDKey{ID: prometheusTarget.ID}] = mysql.ChPrometheusTargetLabelLayout{
			TargetID:          prometheusTarget.ID,
			TargetLabelNames:  targetLabelNames,
			TargetLabelValues: targetLabelValues,
		}
	}
	return keyToItem, true
}

func (l *ChPrometheusTargetLabelLayout) generateKey(dbItem mysql.ChPrometheusTargetLabelLayout) IDKey {
	return IDKey{ID: dbItem.TargetID}
}

func (l *ChPrometheusTargetLabelLayout) generateUpdateInfo(oldItem, newItem mysql.ChPrometheusTargetLabelLayout) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})

	if oldItem.TargetLabelNames != newItem.TargetLabelNames {
		updateInfo["target_label_names"] = newItem.TargetLabelNames
	}
	if oldItem.TargetLabelValues != newItem.TargetLabelValues {
		updateInfo["target_label_values"] = newItem.TargetLabelValues
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
