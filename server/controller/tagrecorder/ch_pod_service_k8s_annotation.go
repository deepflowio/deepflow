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

type ChPodServiceK8sAnnotation struct {
	SubscriberComponent[
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		mysqlmodel.PodService,
		mysqlmodel.ChPodServiceK8sAnnotation,
		IDKeyKey,
	]
}

func NewChPodServiceK8sAnnotation() *ChPodServiceK8sAnnotation {
	mng := &ChPodServiceK8sAnnotation{
		newSubscriberComponent[
			*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
			message.PodServiceDelete,
			mysqlmodel.PodService,
			mysqlmodel.ChPodServiceK8sAnnotation,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]IDKeyKey, 0)
	targetsToAdd := make([]mysqlmodel.ChPodServiceK8sAnnotation, 0)
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodServiceK8sAnnotation, 0)

	if fieldsUpdate.Annotation.IsDifferent() {
		_, oldMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetOld())
		_, newMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())

		for k, v := range newMap {
			targetKey := NewIDKeyKey(sourceID, k)
			oldV, ok := oldMap[k]
			if !ok {
				keysToAdd = append(keysToAdd, targetKey)
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodServiceK8sAnnotation{
					ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
					Key:      k,
					Value:    v,
					L3EPCID:  fieldsUpdate.VPCID.GetNew(),
					PodNsID:  fieldsUpdate.PodNamespaceID.GetNew(),
				})
				continue
			}
			updateInfo := make(map[string]interface{})
			if oldV != v {
				var chItem mysqlmodel.ChPodServiceK8sAnnotation
				db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
				if chItem.ID == 0 {
					keysToAdd = append(keysToAdd, targetKey)
					targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodServiceK8sAnnotation{
						ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
						Key:      k,
						Value:    v,
					})
					continue
				}
				updateInfo["value"] = v
			}
			c.updateOrSync(db, targetKey, updateInfo)
		}
		for k := range oldMap {
			if _, ok := newMap[k]; !ok {
				keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodServiceK8sAnnotation{
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

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodService) (keys []IDKeyKey, targets []mysqlmodel.ChPodServiceK8sAnnotation) {
	_, annotationMap := common.StrToJsonAndMap(source.Annotation)
	for k, v := range annotationMap {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, mysqlmodel.ChPodServiceK8sAnnotation{
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
func (c *ChPodServiceK8sAnnotation) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodServiceK8sAnnotation, db *mysql.DB) {

}
