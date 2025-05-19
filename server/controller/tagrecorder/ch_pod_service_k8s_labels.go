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

type ChPodServiceK8sLabels struct {
	SubscriberComponent[
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		metadbmodel.PodService,
		metadbmodel.ChPodServiceK8sLabels,
		K8sLabelsKey,
	]
}

func NewChPodServiceK8sLabels() *ChPodServiceK8sLabels {
	mng := &ChPodServiceK8sLabels{
		newSubscriberComponent[
			*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
			message.PodServiceDelete,
			metadbmodel.PodService,
			metadbmodel.ChPodServiceK8sLabels,
			K8sLabelsKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *metadb.DB) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Label.IsDifferent() {
		labels, _ := common.StrToJsonAndMap(fieldsUpdate.Label.GetNew())
		if labels != "" {
			updateInfo["labels"] = labels
		}
	}
	if len(updateInfo) > 0 {
		var chItem metadbmodel.ChPodServiceK8sLabels
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]K8sLabelsKey{{ID: sourceID}},
				[]metadbmodel.ChPodServiceK8sLabels{{
					ID:     sourceID,
					Labels: updateInfo["labels"].(string),
				}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, K8sLabelsKey{ID: sourceID}, db)
		}
	}
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) sourceToTarget(md *message.Metadata, item *metadbmodel.PodService) (keys []K8sLabelsKey, targets []metadbmodel.ChPodServiceK8sLabels) {
	if item.Label == "" {
		return
	}
	labels, _ := common.StrToJsonAndMap(item.Label)
	return []K8sLabelsKey{{ID: item.ID}}, []metadbmodel.ChPodServiceK8sLabels{{
		ID:          item.ID,
		Labels:      labels,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) softDeletedTargetsUpdated(targets []metadbmodel.ChPodServiceK8sLabels, db *metadb.DB) {

}
