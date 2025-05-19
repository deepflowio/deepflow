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

type ChPodServiceK8sAnnotation struct {
	SubscriberComponent[
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		metadbmodel.PodService,
		metadbmodel.ChPodServiceK8sAnnotation,
		K8sAnnotationKey,
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
			metadbmodel.PodService,
			metadbmodel.ChPodServiceK8sAnnotation,
			K8sAnnotationKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *metadb.DB) {
	keysToAdd := make([]K8sAnnotationKey, 0)
	targetsToAdd := make([]metadbmodel.ChPodServiceK8sAnnotation, 0)
	keysToDelete := make([]K8sAnnotationKey, 0)
	targetsToDelete := make([]metadbmodel.ChPodServiceK8sAnnotation, 0)

	if fieldsUpdate.Annotation.IsDifferent() {
		_, oldMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetOld())
		_, newMap := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())

		for k, v := range newMap {
			oldV, ok := oldMap[k]
			if !ok {
				keysToAdd = append(keysToAdd, K8sAnnotationKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, metadbmodel.ChPodServiceK8sAnnotation{
					ID:      sourceID,
					Key:     k,
					Value:   v,
					L3EPCID: fieldsUpdate.VPCID.GetNew(),
					PodNsID: fieldsUpdate.PodNamespaceID.GetNew(),
				})
			} else {
				if oldV != v {
					key := K8sAnnotationKey{ID: sourceID, Key: k}
					var chItem metadbmodel.ChPodServiceK8sAnnotation
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, key)
						targetsToAdd = append(targetsToAdd, metadbmodel.ChPodServiceK8sAnnotation{
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
				targetsToDelete = append(targetsToDelete, metadbmodel.ChPodServiceK8sAnnotation{
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
func (c *ChPodServiceK8sAnnotation) sourceToTarget(md *message.Metadata, source *metadbmodel.PodService) (keys []K8sAnnotationKey, targets []metadbmodel.ChPodServiceK8sAnnotation) {
	_, annotationMap := common.StrToJsonAndMap(source.Annotation)
	for k, v := range annotationMap {
		keys = append(keys, K8sAnnotationKey{ID: source.ID, Key: k})
		targets = append(targets, metadbmodel.ChPodServiceK8sAnnotation{
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
func (c *ChPodServiceK8sAnnotation) softDeletedTargetsUpdated(targets []metadbmodel.ChPodServiceK8sAnnotation, db *metadb.DB) {

}
