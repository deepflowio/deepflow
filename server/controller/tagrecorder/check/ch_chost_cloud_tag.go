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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChChostCloudTag struct {
	UpdaterBase[metadbmodel.ChChostCloudTag, CloudTagKey]
}

func NewChChostCloudTag() *ChChostCloudTag {
	updater := &ChChostCloudTag{
		UpdaterBase[metadbmodel.ChChostCloudTag, CloudTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VM_CLOUD_TAG,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (c *ChChostCloudTag) generateNewData() (map[CloudTagKey]metadbmodel.ChChostCloudTag, bool) {
	var vms []metadbmodel.VM
	err := c.db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err), c.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[CloudTagKey]metadbmodel.ChChostCloudTag)
	for _, vm := range vms {
		for k, v := range vm.CloudTags {
			key := CloudTagKey{
				ID:  vm.ID,
				Key: k,
			}
			keyToItem[key] = metadbmodel.ChChostCloudTag{
				ID:       vm.ID,
				Key:      k,
				Value:    v,
				TeamID:   tagrecorder.DomainToTeamID[vm.Domain],
				DomainID: tagrecorder.DomainToDomainID[vm.Domain],
			}
		}
	}
	return keyToItem, true
}

func (c *ChChostCloudTag) generateKey(dbItem metadbmodel.ChChostCloudTag) CloudTagKey {
	return CloudTagKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (c *ChChostCloudTag) generateUpdateInfo(oldItem, newItem metadbmodel.ChChostCloudTag) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
