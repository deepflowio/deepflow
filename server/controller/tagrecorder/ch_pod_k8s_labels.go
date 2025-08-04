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

type ChPodK8sLabels struct {
	SubscriberComponent[
		*message.PodAdd,
		message.PodAdd,
		*message.PodUpdate,
		message.PodUpdate,
		*message.PodDelete,
		message.PodDelete,
		metadbmodel.Pod,
		metadbmodel.ChPodK8sLabels,
		IDKey,
	]
}

func NewChPodK8sLabels() *ChPodK8sLabels {
	mng := &ChPodK8sLabels{
		newSubscriberComponent[
			*message.PodAdd,
			message.PodAdd,
			*message.PodUpdate,
			message.PodUpdate,
			*message.PodDelete,
			message.PodDelete,
			metadbmodel.Pod,
			metadbmodel.ChPodK8sLabels,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) onResourceUpdated(md *message.Metadata, updateMessage *message.PodUpdate) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.PodFieldsUpdate)
	newSource := updateMessage.GetNewMetadbItem().(*metadbmodel.Pod)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Label.IsDifferent() {
		labels, _ := StrToJsonAndMap(fieldsUpdate.Label.GetNew())
		updateInfo["labels"] = labels
	}
	targetKey := IDKey{ID: sourceID}
	if len(updateInfo) > 0 {
		var chItem metadbmodel.ChPodK8sLabels
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]IDKey{targetKey},
				[]metadbmodel.ChPodK8sLabels{{
					ChIDBase:    metadbmodel.ChIDBase{ID: sourceID},
					Labels:      updateInfo["labels"].(string),
					TeamID:      md.GetTeamID(),
					DomainID:    md.GetDomainID(),
					SubDomainID: md.GetSubDomainID(),
				}},
				db,
			)
		}
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) sourceToTarget(md *message.Metadata, source *metadbmodel.Pod) (keys []IDKey, targets []metadbmodel.ChPodK8sLabels) {
	if source.Label == "" {
		return
	}
	labels, _ := StrToJsonAndMap(source.Label)
	return []IDKey{{ID: source.ID}}, []metadbmodel.ChPodK8sLabels{{
		ChIDBase:    metadbmodel.ChIDBase{ID: source.ID},
		Labels:      labels,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) softDeletedTargetsUpdated(targets []metadbmodel.ChPodK8sLabels, db *metadb.DB) {

}
