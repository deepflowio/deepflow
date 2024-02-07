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
	// UpdaterComponent[mysql.ChChostCloudTag, CloudTagKey]
}

func NewChChostCloudTag() *ChChostCloudTag {
	mng := &ChChostCloudTag{
		newSubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChChostCloudTag, CloudTagKey](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_VM_CLOUD_TAG,
		),
		// newUpdaterComponent[mysql.ChChostCloudTag, CloudTagKey](
		// 	RESOURCE_TYPE_CH_VM_CLOUD_TAG,
		// ),
	}
	mng.subscriberDG = mng
	// updater.updaterDG = updater
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate) {
	keysToAdd := make([]CloudTagKey, 0)
	targetsToAdd := make([]mysql.ChChostCloudTag, 0)
	keysToDelete := make([]CloudTagKey, 0)
	targetsToDelete := make([]mysql.ChChostCloudTag, 0)
	var chItem mysql.ChChostCloudTag
	var updateKey CloudTagKey
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.CloudTags.IsDifferent() {
		new := fieldsUpdate.CloudTags.GetNew()
		old := fieldsUpdate.CloudTags.GetOld()
		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, CloudTagKey{ID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysql.ChChostCloudTag{
					ID:    sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = CloudTagKey{ID: sourceID, Key: k}
					updateInfo[k] = v
					mysql.Db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem) // TODO common
					if chItem.ID == 0 {
						keysToAdd = append(keysToAdd, CloudTagKey{ID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, mysql.ChChostCloudTag{
							ID:    sourceID,
							Key:   k,
							Value: v,
						})
					}
				}
			}
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, CloudTagKey{ID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, mysql.ChChostCloudTag{
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
	if len(updateInfo) > 0 {
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, updateKey)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTag) sourceToTarget(source *mysql.VM) (keys []CloudTagKey, targets []mysql.ChChostCloudTag) {
	for k, v := range source.CloudTags {
		keys = append(keys, CloudTagKey{ID: source.ID, Key: k})
		targets = append(targets, mysql.ChChostCloudTag{
			ID:    source.ID,
			Key:   k,
			Value: v,
		})
	}
	return
}

// func (c *ChChostCloudTag) generateNewData() (map[CloudTagKey]mysql.ChChostCloudTag, bool) {
// 	var vms []mysql.VM
// 	err := mysql.Db.Unscoped().Find(&vms).Error
// 	if err != nil {
// 		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err))
// 		return nil, false
// 	}

// 	keyToItem := make(map[CloudTagKey]mysql.ChChostCloudTag)
// 	for _, vm := range vms {
// 		for k, v := range vm.CloudTags {
// 			key := CloudTagKey{
// 				ID:  vm.ID,
// 				Key: k,
// 			}
// 			keyToItem[key] = mysql.ChChostCloudTag{
// 				ID:    vm.ID,
// 				Key:   k,
// 				Value: v,
// 			}
// 		}
// 	}
// 	return keyToItem, true
// }

// func (c *ChChostCloudTag) generateKey(dbItem mysql.ChChostCloudTag) CloudTagKey {
// 	return CloudTagKey{ID: dbItem.ID, Key: dbItem.Key}
// }

// func (c *ChChostCloudTag) generateUpdateInfo(oldItem, newItem mysql.ChChostCloudTag) (map[string]interface{}, bool) {
// 	updateInfo := make(map[string]interface{})
// 	if oldItem.Value != newItem.Value {
// 		updateInfo["value"] = newItem.Value
// 	}
// 	if len(updateInfo) > 0 {
// 		return updateInfo, true
// 	}
// 	return nil, false
// }
