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

type ChChostCloudTag struct {
	SubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChChostCloudTag, CloudTagKey]
}

func NewChChostCloudTag() *ChChostCloudTag {
	mng := &ChChostCloudTag{
		newSubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChChostCloudTag, CloudTagKey](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_VM_CLOUD_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]CloudTagKey, 0)
	targetsToAdd := make([]mysql.ChChostCloudTag, 0)
	keysToDelete := make([]CloudTagKey, 0)
	targetsToDelete := make([]mysql.ChChostCloudTag, 0)
	var chItem mysql.ChChostCloudTag
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.CloudTags.IsDifferent() {
		new := fieldsUpdate.CloudTags.GetNew()
		old := fieldsUpdate.CloudTags.GetOld()
		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, c.newTargetKey(sourceID, k))
				targetsToAdd = append(targetsToAdd, mysql.ChChostCloudTag{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					key := c.newTargetKey(sourceID, k)
					updateInfo["value"] = v
					db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem) // TODO common
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, key)
						targetsToAdd = append(targetsToAdd, mysql.ChChostCloudTag{
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
				keysToDelete = append(keysToDelete, c.newTargetKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, mysql.ChChostCloudTag{
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
func (c *ChChostCloudTag) sourceToTarget(md *message.Metadata, source *mysql.VM) (keys []CloudTagKey, targets []mysql.ChChostCloudTag) {
	for k, v := range source.CloudTags {
		keys = append(keys, c.newTargetKey(source.ID, k))
		targets = append(targets, mysql.ChChostCloudTag{
			ID:       source.ID,
			Key:      k,
			Value:    v,
			TeamID:   md.TeamID,
			DomainID: md.DomainID,
		})
	}
	return
}

func (c *ChChostCloudTag) newTargetKey(id int, key string) CloudTagKey {
	return CloudTagKey{ID: id, Key: key}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) softDeletedTargetsUpdated(targets []mysql.ChChostCloudTag, db *mysql.DB) {

}
