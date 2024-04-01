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

type ChPodK8sLabels struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sLabels, K8sLabelsKey]
}

func NewChPodK8sLabels() *ChPodK8sLabels {
	mng := &ChPodK8sLabels{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sLabels, K8sLabelsKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Label.IsDifferent() {
		updateInfo["labels"] = fieldsUpdate.Label.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodK8sLabels
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sLabelsKey{{ID: sourceID}},
				[]mysql.ChPodK8sLabels{{ID: sourceID, Labels: updateInfo["labels"].(string)}},
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sLabelsKey{ID: sourceID})
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) sourceToTarget(item *mysql.Pod) (keys []K8sLabelsKey, targets []mysql.ChPodK8sLabels) {
	if item.Label == "" {
		return
	}
	return []K8sLabelsKey{{ID: item.ID}}, []mysql.ChPodK8sLabels{{ID: item.ID, Labels: item.Label}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) softDeletedTargetsUpdated(targets []mysql.ChPodK8sLabels) {

}
