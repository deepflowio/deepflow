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

type ChPodK8sLabel struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysqlmodel.Pod, mysqlmodel.ChPodK8sLabel, K8sLabelKey]
}

func NewChPodK8sLabel() *ChPodK8sLabel {
	mng := &ChPodK8sLabel{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysqlmodel.Pod, mysqlmodel.ChPodK8sLabel, K8sLabelKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_K8S_LABEL,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabel) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]K8sLabelKey, 0)
	targetsToAdd := make([]mysqlmodel.ChPodK8sLabel, 0)
	keysToDelete := make([]K8sLabelKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodK8sLabel, 0)
	var chItem mysqlmodel.ChPodK8sLabel
	var updateKey K8sLabelKey
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Label.IsDifferent() {
		_, new := common.StrToJsonAndMap(fieldsUpdate.Label.GetNew())
		_, old := common.StrToJsonAndMap(fieldsUpdate.Label.GetOld())

		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, K8sLabelKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sLabel{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = K8sLabelKey{ID: sourceID, Key: k}
					updateInfo["value"] = v
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, K8sLabelKey{ID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sLabel{
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
				keysToDelete = append(keysToDelete, K8sLabelKey{ID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodK8sLabel{
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
func (c *ChPodK8sLabel) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []K8sLabelKey, targets []mysqlmodel.ChPodK8sLabel) {
	_, labelMap := common.StrToJsonAndMap(source.Label)
	for k, v := range labelMap {
		keys = append(keys, K8sLabelKey{ID: source.ID, Key: k})
		targets = append(targets, mysqlmodel.ChPodK8sLabel{
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
func (c *ChPodK8sLabel) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sLabel, db *mysql.DB) {

}
