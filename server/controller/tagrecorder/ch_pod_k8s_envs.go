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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodK8sEnvs struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, metadbmodel.Pod, metadbmodel.ChPodK8sEnvs, K8sEnvsKey]
}

func NewChPodK8sEnvs() *ChPodK8sEnvs {
	mng := &ChPodK8sEnvs{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, metadbmodel.Pod, metadbmodel.ChPodK8sEnvs, K8sEnvsKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_ENVS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *metadb.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.ENV.IsDifferent() {
		envs, _ := common.StrToJsonAndMap(fieldsUpdate.ENV.GetNew())
		updateInfo["envs"] = envs
	}
	if len(updateInfo) > 0 {
		var chItem metadbmodel.ChPodK8sEnvs
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sEnvsKey{{ID: sourceID}},
				[]metadbmodel.ChPodK8sEnvs{{ID: sourceID, Envs: updateInfo["envs"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sEnvsKey{ID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) sourceToTarget(md *message.Metadata, item *metadbmodel.Pod) (keys []K8sEnvsKey, targets []metadbmodel.ChPodK8sEnvs) {
	if item.ENV == "" {
		return
	}
	envs, _ := common.StrToJsonAndMap(item.ENV)
	return []K8sEnvsKey{{ID: item.ID}}, []metadbmodel.ChPodK8sEnvs{{
		ID:          item.ID,
		Envs:        envs,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) softDeletedTargetsUpdated(targets []metadbmodel.ChPodK8sEnvs, db *metadb.DB) {

}
