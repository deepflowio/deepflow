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
	SubscriberComponent[
		*message.PodAdd,
		message.PodAdd,
		*message.PodUpdate,
		message.PodUpdate,
		*message.PodDelete,
		message.PodDelete,
		mysqlmodel.Pod,
		mysqlmodel.ChPodK8sLabel,
		IDKeyKey,
	]
}

func NewChPodK8sLabel() *ChPodK8sLabel {
	mng := &ChPodK8sLabel{
		newSubscriberComponent[
			*message.PodAdd,
			message.PodAdd,
			*message.PodUpdate,
			message.PodUpdate,
			*message.PodDelete,
			message.PodDelete,
			mysqlmodel.Pod,
			mysqlmodel.ChPodK8sLabel,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_LABEL,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabel) onResourceUpdated(md *message.Metadata, updateMessage *message.PodUpdate) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.PodFieldsUpdate)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.Pod)
	sourceID := newSource.ID
	keysToAdd := make([]IDKeyKey, 0)
	targetsToAdd := make([]mysqlmodel.ChPodK8sLabel, 0)
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodK8sLabel, 0)

	if fieldsUpdate.Label.IsDifferent() {
		_, new := common.StrToJsonAndMap(fieldsUpdate.Label.GetNew())
		_, old := common.StrToJsonAndMap(fieldsUpdate.Label.GetOld())

		for k, v := range new {
			targetKey := NewIDKeyKey(sourceID, k)
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, targetKey)
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sLabel{
					ChIDBase:    mysqlmodel.ChIDBase{ID: sourceID},
					Key:         k,
					Value:       v,
					TeamID:      md.GetTeamID(),
					DomainID:    md.GetDomainID(),
					SubDomainID: md.GetSubDomainID(),
				})
				continue
			}
			updateInfo := make(map[string]interface{})
			if oldV != v {
				var chItem mysqlmodel.ChPodK8sLabel
				db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
				if chItem.ID == 0 {
					keysToAdd = append(keysToAdd, targetKey)
					targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodK8sLabel{
						ChIDBase:    mysqlmodel.ChIDBase{ID: sourceID},
						Key:         k,
						Value:       v,
						TeamID:      md.GetTeamID(),
						DomainID:    md.GetDomainID(),
						SubDomainID: md.GetSubDomainID(),
					})
					continue
				}
				updateInfo["value"] = v
			}
			c.updateOrSync(db, targetKey, updateInfo)
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodK8sLabel{
					ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
					Key:      k,
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
func (c *ChPodK8sLabel) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []IDKeyKey, targets []mysqlmodel.ChPodK8sLabel) {
	_, labelMap := common.StrToJsonAndMap(source.Label)
	for k, v := range labelMap {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, mysqlmodel.ChPodK8sLabel{
			ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
			Key:         k,
			Value:       v,
			TeamID:      md.GetTeamID(),
			DomainID:    md.GetDomainID(),
			SubDomainID: md.GetSubDomainID(),
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabel) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sLabel, db *mysql.DB) {

}
