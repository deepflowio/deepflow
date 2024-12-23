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

type ChPodNSCloudTag struct {
	SubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, metadbmodel.PodNamespace, metadbmodel.ChPodNSCloudTag, CloudTagKey]
}

func NewChPodNSCloudTag() *ChPodNSCloudTag {
	mng := &ChPodNSCloudTag{
		newSubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, metadbmodel.PodNamespace, metadbmodel.ChPodNSCloudTag, CloudTagKey](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTag) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNamespaceFieldsUpdate, db *metadb.DB) {
	keysToAdd := make([]CloudTagKey, 0)
	targetsToAdd := make([]metadbmodel.ChPodNSCloudTag, 0)
	keysToDelete := make([]CloudTagKey, 0)
	targetsToDelete := make([]metadbmodel.ChPodNSCloudTag, 0)
	var chItem metadbmodel.ChPodNSCloudTag
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.CloudTags.IsDifferent() {
		new := fieldsUpdate.CloudTags.GetNew()
		old := fieldsUpdate.CloudTags.GetOld()
		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, CloudTagKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, metadbmodel.ChPodNSCloudTag{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					key := CloudTagKey{ID: sourceID, Key: k}
					updateInfo["value"] = v
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, key)
						targetsToAdd = append(targetsToAdd, metadbmodel.ChPodNSCloudTag{
							ID:    sourceID,
							Key:   k,
							Value: v,
						})
					} else {
						c.SubscriberComponent.dbOperator.update(chItem, updateInfo, key, db)
					}
				}
			}
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, CloudTagKey{ID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, metadbmodel.ChPodNSCloudTag{
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

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTag) sourceToTarget(md *message.Metadata, source *metadbmodel.PodNamespace) (keys []CloudTagKey, targets []metadbmodel.ChPodNSCloudTag) {
	for k, v := range source.CloudTags {
		keys = append(keys, CloudTagKey{ID: source.ID, Key: k})
		targets = append(targets, metadbmodel.ChPodNSCloudTag{
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
func (c *ChPodNSCloudTag) softDeletedTargetsUpdated(targets []metadbmodel.ChPodNSCloudTag, db *metadb.DB) {

}
