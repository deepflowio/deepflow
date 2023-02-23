/*
 * Copyright (c) 2022 Yunshan Networks
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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChChostCloudTags struct {
	UpdaterBase[mysql.ChChostCloudTags, CloudTagsKey]
}

func NewChChostCloudTags() *ChChostCloudTags {
	updater := &ChChostCloudTags{
		UpdaterBase[mysql.ChChostCloudTags, CloudTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VM_CLOUD_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (c *ChChostCloudTags) generateNewData() (map[CloudTagsKey]mysql.ChChostCloudTags, bool) {
	var vms []mysql.VM
	err := mysql.Db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[CloudTagsKey]mysql.ChChostCloudTags)
	for _, vm := range vms {
		cloudTagsMap := map[string]string{}
		splitCloudTags := strings.Split(vm.CloudTags, ", ")
		for _, singleCloudTag := range splitCloudTags {
			splitSingleLabel := strings.Split(singleCloudTag, ":")
			if len(splitSingleLabel) == 2 {
				cloudTagsMap[splitSingleLabel[0]] = splitSingleLabel[1]
			}
		}
		if len(cloudTagsMap) > 0 {
			cloudTagsStr, err := json.Marshal(cloudTagsMap)
			if err != nil {
				log.Error(err)
				return nil, false
			}
			key := CloudTagsKey{
				ID: vm.ID,
			}
			keyToItem[key] = mysql.ChChostCloudTags{
				ID:        vm.ID,
				CloudTags: string(cloudTagsStr),
			}
		}
	}
	return keyToItem, true
}

func (c *ChChostCloudTags) generateKey(dbItem mysql.ChChostCloudTags) CloudTagsKey {
	return CloudTagsKey{ID: dbItem.ID}
}

func (c *ChChostCloudTags) generateUpdateInfo(oldItem, newItem mysql.ChChostCloudTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.CloudTags != newItem.CloudTags {
		updateInfo["cloud_tags"] = newItem.CloudTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
