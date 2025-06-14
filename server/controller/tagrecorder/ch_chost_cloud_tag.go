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

type ChChostCloudTag struct {
	SubscriberComponent[
		*message.VMAdd,
		message.VMAdd,
		*message.VMFieldsUpdate,
		message.VMFieldsUpdate,
		*message.VMDelete,
		message.VMDelete,
		mysqlmodel.VM,
		mysqlmodel.ChChostCloudTag,
		IDKeyKey,
	]
}

func NewChChostCloudTag() *ChChostCloudTag {
	mng := &ChChostCloudTag{
		newSubscriberComponent[
			*message.VMAdd,
			message.VMAdd,
			*message.VMFieldsUpdate,
			message.VMFieldsUpdate,
			*message.VMDelete,
			message.VMDelete,
			mysqlmodel.VM,
			mysqlmodel.ChChostCloudTag,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_CHOST_CLOUD_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate, db *mysql.DB) {
	keysToAdd := make([]IDKeyKey, 0)
	targetsToAdd := make([]mysqlmodel.ChChostCloudTag, 0)
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]mysqlmodel.ChChostCloudTag, 0)

	if fieldsUpdate.CloudTags.IsDifferent() {
		new := fieldsUpdate.CloudTags.GetNew()
		old := fieldsUpdate.CloudTags.GetOld()
		for k, v := range new {
			oldV, ok := old[k]
			targetKey := NewIDKeyKey(sourceID, k)
			if !ok {
				keysToAdd = append(keysToAdd, targetKey)
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChChostCloudTag{
					ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
					Key:      k,
					Value:    v,
				})
				continue
			}
			updateInfo := make(map[string]interface{})
			if oldV != v {
				var chItem mysqlmodel.ChChostCloudTag
				db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem) // TODO common
				if chItem.ID == 0 {
					keysToAdd = append(keysToAdd, targetKey)
					targetsToAdd = append(targetsToAdd, mysqlmodel.ChChostCloudTag{
						ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
						Key:      k,
						Value:    v,
					})
					continue
				}
				updateInfo["value"] = v
			}
			c.updateOrSync(db, targetKey, updateInfo)
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChChostCloudTag{
					ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
					Key:      k,
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
func (c *ChChostCloudTag) sourceToTarget(md *message.Metadata, source *mysqlmodel.VM) (keys []IDKeyKey, targets []mysqlmodel.ChChostCloudTag) {
	for k, v := range source.CloudTags {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, mysqlmodel.ChChostCloudTag{
			ChIDBase: mysqlmodel.ChIDBase{ID: source.ID},
			Key:      k,
			Value:    v,
			TeamID:   md.TeamID,
			DomainID: md.DomainID,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) softDeletedTargetsUpdated(targets []mysqlmodel.ChChostCloudTag, db *mysql.DB) {

}
