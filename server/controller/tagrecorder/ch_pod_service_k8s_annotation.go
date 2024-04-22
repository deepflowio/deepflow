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

type ChPodServiceK8sAnnotation struct {
	SubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sAnnotation, K8sAnnotationKey]
}

func NewChPodServiceK8sAnnotation() *ChPodServiceK8sAnnotation {
	mng := &ChPodServiceK8sAnnotation{
		newSubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sAnnotation, K8sAnnotationKey](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_K8S_ANNOTATION,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]K8sAnnotationKey, 0)
	targetsToAdd := make([]mysql.ChPodServiceK8sAnnotation, 0)
	keysToDelete := make([]K8sAnnotationKey, 0)
	targetsToDelete := make([]mysql.ChPodServiceK8sAnnotation, 0)

	if fieldsUpdate.Annotation.IsDifferent() {
		_, oldMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetOld())
		_, newMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())

		for k, v := range newMap {
			oldV, ok := oldMap[k]
			if !ok {
				keysToAdd = append(keysToAdd, K8sAnnotationKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysql.ChPodServiceK8sAnnotation{
					ID:      sourceID,
					Key:     k,
					Value:   v,
					L3EPCID: fieldsUpdate.VPCID.GetNew(),
					PodNsID: fieldsUpdate.PodNamespaceID.GetNew(),
				})
			} else {
				if oldV != v {
					key := K8sAnnotationKey{ID: sourceID, Key: k}
					var chItem mysql.ChPodServiceK8sAnnotation
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, key)
						targetsToAdd = append(targetsToAdd, mysql.ChPodServiceK8sAnnotation{
							ID:    sourceID,
							Key:   k,
							Value: v,
						})
					} else {
						c.SubscriberComponent.dbOperator.update(chItem, map[string]interface{}{"value": v}, key, db)
					}
				}
			}
		}
		for k := range oldMap {
			if _, ok := newMap[k]; !ok {
				keysToDelete = append(keysToDelete, K8sAnnotationKey{ID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, mysql.ChPodServiceK8sAnnotation{
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

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) sourceToTarget(md *message.Metadata, source *mysql.PodService) (keys []K8sAnnotationKey, targets []mysql.ChPodServiceK8sAnnotation) {
	_, annotationMap := common.StrToJsonAndMap(source.Annotation)
	for k, v := range annotationMap {
		keys = append(keys, K8sAnnotationKey{ID: source.ID, Key: k})
		targets = append(targets, mysql.ChPodServiceK8sAnnotation{
			ID:       source.ID,
			Key:      k,
			Value:    v,
			TeamID:   md.TeamID,
			DomainID: md.DomainID,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) softDeletedTargetsUpdated(targets []mysql.ChPodServiceK8sAnnotation, db *mysql.DB) {

}
