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
	"encoding/json"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChChostCloudTags struct {
	UpdaterBase[metadbmodel.ChChostCloudTags, CloudTagsKey]
}

func NewChChostCloudTags() *ChChostCloudTags {
	updater := &ChChostCloudTags{
		UpdaterBase[metadbmodel.ChChostCloudTags, CloudTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VM_CLOUD_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (c *ChChostCloudTags) generateNewData() (map[CloudTagsKey]metadbmodel.ChChostCloudTags, bool) {
	var vms []metadbmodel.VM
	err := c.db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err), c.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[CloudTagsKey]metadbmodel.ChChostCloudTags)
	for _, vm := range vms {
		cloudTagsMap := map[string]string{}
		for k, v := range vm.CloudTags {
			cloudTagsMap[k] = v
		}
		if len(cloudTagsMap) > 0 {
			cloudTagsStr, err := json.Marshal(cloudTagsMap)
			if err != nil {
				log.Error(err, c.db.LogPrefixORGID)
				return nil, false
			}
			key := CloudTagsKey{
				ID: vm.ID,
			}
			keyToItem[key] = metadbmodel.ChChostCloudTags{
				ID:        vm.ID,
				CloudTags: string(cloudTagsStr),
				TeamID:    tagrecorder.DomainToTeamID[vm.Domain],
				DomainID:  tagrecorder.DomainToDomainID[vm.Domain],
			}
		}
	}
	return keyToItem, true
}

func (c *ChChostCloudTags) generateKey(dbItem metadbmodel.ChChostCloudTags) CloudTagsKey {
	return CloudTagsKey{ID: dbItem.ID}
}

func (c *ChChostCloudTags) generateUpdateInfo(oldItem, newItem metadbmodel.ChChostCloudTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.CloudTags != newItem.CloudTags {
		updateInfo["cloud_tags"] = newItem.CloudTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
