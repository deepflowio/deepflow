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

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodK8sEnv struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sEnv, K8sEnvKey]
}

func NewChPodK8sEnv() *ChPodK8sEnv {
	mng := &ChPodK8sEnv{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChPodK8sEnv, K8sEnvKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_ENV,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]K8sEnvKey, 0)
	targetsToAdd := make([]mysql.ChPodK8sEnv, 0)
	keysToDelete := make([]K8sEnvKey, 0)
	targetsToDelete := make([]mysql.ChPodK8sEnv, 0)
	var chItem mysql.ChPodK8sEnv
	var updateKey K8sEnvKey
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.ENV.IsDifferent() {
		new := map[string]string{}
		old := map[string]string{}
		newStr := fieldsUpdate.ENV.GetNew()
		oldStr := fieldsUpdate.ENV.GetOld()
		splitNews := strings.Split(newStr, ", ")
		splitOlds := strings.Split(oldStr, ", ")

		for _, splitNew := range splitNews {
			splitSingleTag := strings.Split(splitNew, ":")
			if len(splitSingleTag) == 2 {
				new[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		for _, splitOld := range splitOlds {
			splitSingleTag := strings.Split(splitOld, ":")
			if len(splitSingleTag) == 2 {
				old[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, K8sEnvKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysql.ChPodK8sEnv{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = K8sEnvKey{ID: sourceID, Key: k}
					updateInfo[k] = v
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, K8sEnvKey{ID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, mysql.ChPodK8sEnv{
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
				targetsToDelete = append(targetsToDelete, mysql.ChPodK8sEnv{
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
func (c *ChPodK8sEnv) sourceToTarget(source *mysql.Pod) (keys []K8sEnvKey, targets []mysql.ChPodK8sEnv) {
	envMap := map[string]string{}
	splitTags := strings.Split(source.ENV, ", ")

	for _, splitTag := range splitTags {
		splitSingleTag := strings.Split(splitTag, ":")
		if len(splitSingleTag) == 2 {
			envMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
		}
	}
	for k, v := range envMap {
		keys = append(keys, K8sEnvKey{ID: source.ID, Key: k})
		targets = append(targets, mysql.ChPodK8sEnv{
			ID:    source.ID,
			Key:   k,
			Value: v,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) softDeletedTargetsUpdated(targets []mysql.ChPodK8sEnv, db *mysql.DB) {

}
