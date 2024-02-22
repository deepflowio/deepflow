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
func (c *ChPodServiceK8sAnnotation) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate) {
	keysToAdd := make([]K8sAnnotationKey, 0)
	targetsToAdd := make([]mysql.ChPodServiceK8sAnnotation, 0)
	keysToDelete := make([]K8sAnnotationKey, 0)
	targetsToDelete := make([]mysql.ChPodServiceK8sAnnotation, 0)
	if fieldsUpdate.Annotation.IsDifferent() {
		new := fieldsUpdate.Annotation.GetNew()
		old := fieldsUpdate.Annotation.GetOld()
		oldMap := make(map[string]string)
		newMap := make(map[string]string)

		for _, pairStr := range strings.Split(old, ", ") {
			pair := strings.Split(pairStr, ":")
			if len(pair) == 2 {
				oldMap[pair[0]] = pair[1]
			}
		}
		for _, pairStr := range strings.Split(new, ", ") {
			pair := strings.Split(pairStr, ":")
			if len(pair) == 2 {
				k, v := pair[0], pair[1]
				newMap[k] = v

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
						mysql.Db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
						if chItem.ID == 0 {
							keysToAdd = append(keysToAdd, key)
							targetsToAdd = append(targetsToAdd, mysql.ChPodServiceK8sAnnotation{
								ID:    sourceID,
								Key:   k,
								Value: v,
							})
						} else {
							c.SubscriberComponent.dbOperator.update(chItem, map[string]interface{}{"value": v}, key)
						}
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
		c.SubscriberComponent.dbOperator.add(keysToAdd, targetsToAdd)
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete)
	}
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotation) sourceToTarget(source *mysql.PodService) (keys []K8sAnnotationKey, targets []mysql.ChPodServiceK8sAnnotation) {
	splitAnnotation := strings.Split(source.Annotation, ", ")
	for _, singleAnnotation := range splitAnnotation {
		splitSingleAnnotation := strings.Split(singleAnnotation, ":")
		if len(splitSingleAnnotation) == 2 {
			keys = append(keys, K8sAnnotationKey{ID: source.ID, Key: splitSingleAnnotation[0]})
			targets = append(targets, mysql.ChPodServiceK8sAnnotation{
				ID:    source.ID,
				Key:   splitSingleAnnotation[0],
				Value: splitSingleAnnotation[1],
			})
		}
	}
	return
}
