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

type ChPodServiceK8sLabel struct {
	SubscriberComponent[
		*message.AddedPodServices,
		message.AddedPodServices,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		metadbmodel.PodService,
		metadbmodel.ChPodServiceK8sLabel,
		IDKeyKey,
	]
}

func NewChPodServiceK8sLabel() *ChPodServiceK8sLabel {
	mng := &ChPodServiceK8sLabel{
		newSubscriberComponent[
			*message.AddedPodServices,
			message.AddedPodServices,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			metadbmodel.PodService,
			metadbmodel.ChPodServiceK8sLabel,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabel) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodService) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedPodServiceFields)
	newSource := updateMessage.GetNewMetadbItem().(*metadbmodel.PodService)
	sourceID := newSource.ID
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]metadbmodel.ChPodServiceK8sLabel, 0)

	if fieldsUpdate.Label.IsDifferent() {
		_, oldMap := StrToJsonAndMap(fieldsUpdate.Label.GetOld())
		_, newMap := StrToJsonAndMap(fieldsUpdate.Label.GetNew())

		for k := range oldMap {
			if _, ok := newMap[k]; !ok {
				keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, metadbmodel.ChPodServiceK8sLabel{
					ChIDBase: metadbmodel.ChIDBase{ID: sourceID},
					Key:      k,
				})
			}
		}
	}

	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete, db)
	}
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabel) sourceToTarget(md *message.Metadata, source *metadbmodel.PodService) (keys []IDKeyKey, targets []metadbmodel.ChPodServiceK8sLabel) {
	_, labelMap := StrToJsonAndMap(source.Label)

	for k, v := range labelMap {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, metadbmodel.ChPodServiceK8sLabel{
			ChIDBase:    metadbmodel.ChIDBase{ID: source.ID},
			Key:         k,
			Value:       v,
			L3EPCID:     source.VPCID,
			PodNsID:     source.PodNamespaceID,
			TeamID:      md.GetTeamID(),
			DomainID:    md.GetDomainID(),
			SubDomainID: md.GetSubDomainID(),
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabel) softDeletedTargetsUpdated(targets []metadbmodel.ChPodServiceK8sLabel, db *metadb.DB) {

}
