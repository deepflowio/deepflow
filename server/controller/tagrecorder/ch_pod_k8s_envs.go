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

type ChPodK8sEnvs struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sEnvs, K8sEnvsKey]
}

func NewChPodK8sEnvs() *ChPodK8sEnvs {
	mng := &ChPodK8sEnvs{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sEnvs, K8sEnvsKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_ENVS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.ENV.IsDifferent() {
		updateInfo["envs"] = fieldsUpdate.ENV.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodK8sEnvs
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sEnvsKey{{ID: sourceID}},
				[]mysql.ChPodK8sEnvs{{ID: sourceID, Envs: updateInfo["envs"].(string)}},
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sEnvsKey{ID: sourceID})
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) sourceToTarget(item *mysql.Pod) (keys []K8sEnvsKey, targets []mysql.ChPodK8sEnvs) {
	if item.ENV == "" {
		return
	}
	return []K8sEnvsKey{{ID: item.ID}}, []mysql.ChPodK8sEnvs{{ID: item.ID, Envs: item.ENV}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) softDeletedTargetsUpdated(targets []mysql.ChPodK8sEnvs) {

}
