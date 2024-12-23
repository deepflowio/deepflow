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

type ChPodNSCloudTags struct {
	UpdaterBase[metadbmodel.ChPodNSCloudTags, CloudTagsKey]
}

func NewChPodNSCloudTags() *ChPodNSCloudTags {
	updater := &ChPodNSCloudTags{
		UpdaterBase[metadbmodel.ChPodNSCloudTags, CloudTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNSCloudTags) generateNewData() (map[CloudTagsKey]metadbmodel.ChPodNSCloudTags, bool) {
	var podNamespaces []metadbmodel.PodNamespace
	err := p.db.Unscoped().Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[CloudTagsKey]metadbmodel.ChPodNSCloudTags)
	for _, podNamespace := range podNamespaces {
		teamID, err := tagrecorder.GetTeamID(podNamespace.Domain, podNamespace.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podNamespace, p.db.LogPrefixORGID)
		}

		cloudTagsMap := map[string]string{}
		for k, v := range podNamespace.CloudTags {
			cloudTagsMap[k] = v
		}
		if len(cloudTagsMap) > 0 {
			cloudTagsStr, err := json.Marshal(cloudTagsMap)
			if err != nil {
				log.Error(err, p.db.LogPrefixORGID)
				return nil, false
			}
			key := CloudTagsKey{
				ID: podNamespace.ID,
			}
			keyToItem[key] = metadbmodel.ChPodNSCloudTags{
				ID:          podNamespace.ID,
				CloudTags:   string(cloudTagsStr),
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podNamespace.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podNamespace.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNSCloudTags) generateKey(dbItem metadbmodel.ChPodNSCloudTags) CloudTagsKey {
	return CloudTagsKey{ID: dbItem.ID}
}

func (p *ChPodNSCloudTags) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodNSCloudTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.CloudTags != newItem.CloudTags {
		updateInfo["cloud_tags"] = newItem.CloudTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
