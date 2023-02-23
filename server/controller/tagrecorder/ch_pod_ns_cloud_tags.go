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

type ChPodNSCloudTags struct {
	UpdaterBase[mysql.ChPodNSCloudTags, CloudTagsKey]
}

func NewChPodNSCloudTags() *ChPodNSCloudTags {
	updater := &ChPodNSCloudTags{
		UpdaterBase[mysql.ChPodNSCloudTags, CloudTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNSCloudTags) generateNewData() (map[CloudTagsKey]mysql.ChPodNSCloudTags, bool) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Unscoped().Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[CloudTagsKey]mysql.ChPodNSCloudTags)
	for _, podNamespace := range podNamespaces {
		cloudTagsMap := map[string]string{}
		splitCloudTags := strings.Split(podNamespace.CloudTags, ", ")
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
				ID: podNamespace.ID,
			}
			keyToItem[key] = mysql.ChPodNSCloudTags{
				ID:        podNamespace.ID,
				CloudTags: string(cloudTagsStr),
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNSCloudTags) generateKey(dbItem mysql.ChPodNSCloudTags) CloudTagsKey {
	return CloudTagsKey{ID: dbItem.ID}
}

func (p *ChPodNSCloudTags) generateUpdateInfo(oldItem, newItem mysql.ChPodNSCloudTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.CloudTags != newItem.CloudTags {
		updateInfo["cloud_tags"] = newItem.CloudTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
