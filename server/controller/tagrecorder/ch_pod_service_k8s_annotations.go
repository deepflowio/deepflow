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

type ChPodServiceK8sAnnotations struct {
	SubscriberComponent[
		*message.AddedPodServices,
		message.AddedPodServices,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		metadbmodel.PodService,
		metadbmodel.ChPodServiceK8sAnnotations,
		IDKey,
	]
}

func NewChPodServiceK8sAnnotations() *ChPodServiceK8sAnnotations {
	mng := &ChPodServiceK8sAnnotations{
		newSubscriberComponent[
			*message.AddedPodServices,
			message.AddedPodServices,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			metadbmodel.PodService,
			metadbmodel.ChPodServiceK8sAnnotations,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodService) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedPodServiceFields)
	newSource := updateMessage.GetNewMetadbItem().(*metadbmodel.PodService)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})
	var chItem metadbmodel.ChPodServiceK8sAnnotations

	if fieldsUpdate.Annotation.IsDifferent() {
		annotations, _ := StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())
		if annotations != "" {
			updateInfo["annotations"] = annotations
		}
	}
	targetKey := IDKey{ID: sourceID}
	if len(updateInfo) > 0 {
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]IDKey{targetKey},
				[]metadbmodel.ChPodServiceK8sAnnotations{{
					ChIDBase:    metadbmodel.ChIDBase{ID: sourceID},
					Annotations: updateInfo["annotations"].(string),
					L3EPCID:     newSource.VPCID,
					PodNsID:     newSource.PodNamespaceID,
					TeamID:      md.GetTeamID(),
					DomainID:    md.GetDomainID(),
					SubDomainID: md.GetSubDomainID(),
				}},
				db,
			)
			return
		}
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) sourceToTarget(md *message.Metadata, source *metadbmodel.PodService) (keys []IDKey, targets []metadbmodel.ChPodServiceK8sAnnotations) {
	if source.Annotation == "" {
		return
	}
	annotations, _ := StrToJsonAndMap(source.Annotation)
	return []IDKey{{ID: source.ID}}, []metadbmodel.ChPodServiceK8sAnnotations{{
		ChIDBase:    metadbmodel.ChIDBase{ID: source.ID},
		Annotations: annotations,
		L3EPCID:     source.VPCID,
		PodNsID:     source.PodNamespaceID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) softDeletedTargetsUpdated(targets []metadbmodel.ChPodServiceK8sAnnotations, db *metadb.DB) {

}
