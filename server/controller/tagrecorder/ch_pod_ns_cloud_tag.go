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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPodNSCloudTag struct {
	UpdaterBase[mysql.ChPodNSCloudTag, CloudTagKey]
}

func NewChPodNSCloudTag() *ChPodNSCloudTag {
	updater := &ChPodNSCloudTag{
		UpdaterBase[mysql.ChPodNSCloudTag, CloudTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNSCloudTag) generateNewData() (map[CloudTagKey]mysql.ChPodNSCloudTag, bool) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Unscoped().Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[CloudTagKey]mysql.ChPodNSCloudTag)
	for _, podNamespace := range podNamespaces {
		splitTags := strings.Split(podNamespace.CloudTags, ", ")
		for _, singleTag := range splitTags {
			splitSingleTag := strings.Split(singleTag, ":")
			if len(splitSingleTag) == 2 {
				key := CloudTagKey{
					ID:  podNamespace.ID,
					Key: splitSingleTag[0],
				}
				keyToItem[key] = mysql.ChPodNSCloudTag{
					ID:    podNamespace.ID,
					Key:   splitSingleTag[0],
					Value: splitSingleTag[1],
				}
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNSCloudTag) generateKey(dbItem mysql.ChPodNSCloudTag) CloudTagKey {
	return CloudTagKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (p *ChPodNSCloudTag) generateUpdateInfo(oldItem, newItem mysql.ChPodNSCloudTag) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
