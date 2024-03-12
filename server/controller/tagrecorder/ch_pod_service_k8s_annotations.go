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

type ChPodServiceK8sAnnotations struct {
	SubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sAnnotations, K8sAnnotationsKey]
}

func NewChPodServiceK8sAnnotations() *ChPodServiceK8sAnnotations {
	mng := &ChPodServiceK8sAnnotations{
		newSubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChPodServiceK8sAnnotations, K8sAnnotationsKey](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_K8S_ANNOTATIONS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	var annotations string
	var chItem mysql.ChPodServiceK8sAnnotations
	if fieldsUpdate.Annotation.IsDifferent() {
		annotations = common.StrToJsonstr(fieldsUpdate.Annotation.GetNew())
		if annotations != "" {
			updateInfo["annotations"] = annotations
		}
	}
	if len(updateInfo) > 0 {
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sAnnotationsKey{{ID: sourceID}},
				[]mysql.ChPodServiceK8sAnnotations{{
					ID:          sourceID,
					Annotations: updateInfo["annotations"].(string),
				}},
			)
		} else {
			c.SubscriberComponent.dbOperator.update(
				chItem,
				updateInfo,
				K8sAnnotationsKey{ID: sourceID})
		}
	}
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) sourceToTarget(item *mysql.PodService) (keys []K8sAnnotationsKey, targets []mysql.ChPodServiceK8sAnnotations) {
	if item.Annotation == "" {
		return
	}
	return []K8sAnnotationsKey{{ID: item.ID}}, []mysql.ChPodServiceK8sAnnotations{{
		ID:          item.ID,
		Annotations: common.StrToJsonstr(item.Annotation),
	}}
}
