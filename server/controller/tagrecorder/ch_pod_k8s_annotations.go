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

type ChPodK8sAnnotations struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sAnnotations, K8sAnnotationsKey]
}

func NewChPodK8sAnnotations() *ChPodK8sAnnotations {
	mng := &ChPodK8sAnnotations{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sAnnotations, K8sAnnotationsKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_ANNOTATIONS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Annotation.IsDifferent() {
		updateInfo["annotations"] = fieldsUpdate.Annotation.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodK8sAnnotations
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sAnnotationsKey{{ID: sourceID}},
				[]mysql.ChPodK8sAnnotations{{ID: sourceID, Annotations: updateInfo["annotations"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sAnnotationsKey{ID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) sourceToTarget(item *mysql.Pod) (keys []K8sAnnotationsKey, targets []mysql.ChPodK8sAnnotations) {
	if item.Annotation == "" {
		return
	}
	return []K8sAnnotationsKey{{ID: item.ID}}, []mysql.ChPodK8sAnnotations{{ID: item.ID, Annotations: item.Annotation}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) softDeletedTargetsUpdated(targets []mysql.ChPodK8sAnnotations, db *mysql.DB) {

}
