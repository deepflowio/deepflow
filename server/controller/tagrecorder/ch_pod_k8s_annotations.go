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

type ChPodK8sAnnotations struct {
	SubscriberComponent[
		*message.PodAdd,
		message.PodAdd,
		*message.PodFieldsUpdate,
		message.PodFieldsUpdate,
		*message.PodDelete,
		message.PodDelete,
		mysqlmodel.Pod,
		mysqlmodel.ChPodK8sAnnotations,
		K8sAnnotationsKey,
	]
}

func NewChPodK8sAnnotations() *ChPodK8sAnnotations {
	mng := &ChPodK8sAnnotations{
		newSubscriberComponent[
			*message.PodAdd,
			message.PodAdd,
			*message.PodFieldsUpdate,
			message.PodFieldsUpdate,
			*message.PodDelete,
			message.PodDelete,
			mysqlmodel.Pod,
			mysqlmodel.ChPodK8sAnnotations,
			K8sAnnotationsKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_ANNOTATIONS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Annotation.IsDifferent() {
		annotations, _ := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())
		updateInfo["annotations"] = annotations
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChPodK8sAnnotations
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sAnnotationsKey{{ID: sourceID}},
				[]mysqlmodel.ChPodK8sAnnotations{{ID: sourceID, Annotations: updateInfo["annotations"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sAnnotationsKey{ID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) sourceToTarget(md *message.Metadata, item *mysqlmodel.Pod) (keys []K8sAnnotationsKey, targets []mysqlmodel.ChPodK8sAnnotations) {
	if item.Annotation == "" {
		return
	}
	annotations, _ := common.StrToJsonAndMap(item.Annotation)
	return []K8sAnnotationsKey{{ID: item.ID}}, []mysqlmodel.ChPodK8sAnnotations{{
		ID:          item.ID,
		Annotations: annotations,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sAnnotations) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sAnnotations, db *mysql.DB) {

}
