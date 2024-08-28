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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodK8sEnv struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysqlmodel.Pod, mysqlmodel.ChPodK8sEnv, K8sEnvKey]
}

func NewChPodK8sEnv() *ChPodK8sEnv {
	mng := &ChPodK8sEnv{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysqlmodel.Pod, mysqlmodel.ChPodK8sEnv, K8sEnvKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_ENV,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]K8sEnvKey, 0)
	targetsToAdd := make([]mysqlmodel.ChPodK8sEnv, 0)
	keysToDelete := make([]K8sEnvKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodK8sEnv, 0)
	var chItem mysqlmodel.ChPodK8sEnv
	var updateKey K8sEnvKey
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.ENV.IsDifferent() {
		_, new := common.StrToJsonAndMap(fieldsUpdate.ENV.GetNew())
		_, old := common.StrToJsonAndMap(fieldsUpdate.ENV.GetOld())

		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, K8sEnvKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sEnv{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = K8sEnvKey{ID: sourceID, Key: k}
					updateInfo["value"] = v
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, K8sEnvKey{ID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sEnv{
							ID:    sourceID,
							Key:   k,
							Value: v,
						})
					} else if len(updateInfo) > 0 {
						c.SubscriberComponent.dbOperator.update(chItem, updateInfo, updateKey, db)
					}
				}
			}
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, K8sEnvKey{ID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodK8sEnv{
					ID:  sourceID,
					Key: k,
				})
			}
		}
	}
	if len(keysToAdd) > 0 {
		c.SubscriberComponent.dbOperator.add(keysToAdd, targetsToAdd, db)
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete, db)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []K8sEnvKey, targets []mysqlmodel.ChPodK8sEnv) {
	_, envMap := common.StrToJsonAndMap(source.ENV)

	for k, v := range envMap {
		keys = append(keys, K8sEnvKey{ID: source.ID, Key: k})
		targets = append(targets, mysqlmodel.ChPodK8sEnv{
			ID:          source.ID,
			Key:         k,
			Value:       v,
			TeamID:      md.TeamID,
			DomainID:    md.DomainID,
			SubDomainID: md.SubDomainID,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sEnv, db *mysql.DB) {

}
