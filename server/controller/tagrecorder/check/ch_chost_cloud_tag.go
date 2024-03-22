/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChChostCloudTag struct {
	UpdaterBase[mysql.ChChostCloudTag, CloudTagKey]
}

func NewChChostCloudTag() *ChChostCloudTag {
	updater := &ChChostCloudTag{
		UpdaterBase[mysql.ChChostCloudTag, CloudTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VM_CLOUD_TAG,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (c *ChChostCloudTag) generateNewData() (map[CloudTagKey]mysql.ChChostCloudTag, bool) {
	var vms []mysql.VM
	err := mysql.Db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[CloudTagKey]mysql.ChChostCloudTag)
	for _, vm := range vms {
		for k, v := range vm.CloudTags {
			key := CloudTagKey{
				ID:  vm.ID,
				Key: k,
			}
			keyToItem[key] = mysql.ChChostCloudTag{
				ID:    vm.ID,
				Key:   k,
				Value: v,
			}
		}
	}
	return keyToItem, true
}

func (c *ChChostCloudTag) generateKey(dbItem mysql.ChChostCloudTag) CloudTagKey {
	return CloudTagKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (c *ChChostCloudTag) generateUpdateInfo(oldItem, newItem mysql.ChChostCloudTag) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
