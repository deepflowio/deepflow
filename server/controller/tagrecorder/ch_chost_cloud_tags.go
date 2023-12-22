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

func (c *ChChostCloudTags) getNewData() ([]mysql.ChChostCloudTags, bool) {
	var vms []mysql.VM
	err := mysql.Db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChChostCloudTags, len(vms))
	i := 0
	for _, vm := range vms {
		cloudTagsMap := map[string]string{}
		for k, v := range vm.CloudTags {
			cloudTagsMap[k] = v
		}
		if len(cloudTagsMap) > 0 {
			cloudTagsStr, err := json.Marshal(cloudTagsMap)
			if err != nil {
				log.Error(err)
				return nil, false
			}
			items[i] = mysql.ChChostCloudTags{
				ID:        vm.ID,
				CloudTags: string(cloudTagsStr),
			}
			i++
		}
	}
	return items, true
}

func (c *ChChostCloudTags) generateNewData() (map[CloudTagsKey]mysql.ChChostCloudTags, bool) {
	items, ok := c.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[CloudTagsKey]mysql.ChChostCloudTags, len(items))
	for _, item := range items {
		keyToItem[CloudTagsKey{item.ID}] = item
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
