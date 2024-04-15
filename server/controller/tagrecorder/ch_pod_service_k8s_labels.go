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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodServiceK8sLabels struct {
	SubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sLabels, K8sLabelsKey]
}

func NewChPodServiceK8sLabels() *ChPodServiceK8sLabels {
	mng := &ChPodServiceK8sLabels{
		newSubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sLabels, K8sLabelsKey](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	var labels string
	if fieldsUpdate.Label.IsDifferent() {
		labels = common.StrToJsonstr(fieldsUpdate.Label.GetNew())
		if labels != "" {
			updateInfo["labels"] = labels
		}
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodServiceK8sLabels
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sLabelsKey{{ID: sourceID}},
				[]mysql.ChPodServiceK8sLabels{{
					ID:     sourceID,
					Labels: updateInfo["labels"].(string),
				}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sLabelsKey{ID: sourceID}, db)
		}
	}
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) sourceToTarget(md *message.Metadata, item *mysql.PodService) (keys []K8sLabelsKey, targets []mysql.ChPodServiceK8sLabels) {
	if item.Label == "" {
		return
	}
	return []K8sLabelsKey{{ID: item.ID}}, []mysql.ChPodServiceK8sLabels{{
		ID:       item.ID,
		Labels:   common.StrToJsonstr(item.Label),
		TeamID:   md.TeamID,
		DomainID: md.DomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) softDeletedTargetsUpdated(targets []mysql.ChPodServiceK8sLabels, db *mysql.DB) {

}
