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
	"encoding/json"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodNSCloudTags struct {
	SubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, mysql.PodNamespace, mysql.ChPodNSCloudTags, CloudTagsKey]
}

func NewChPodNSCloudTags() *ChPodNSCloudTags {
	mng := &ChPodNSCloudTags{
		newSubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, mysql.PodNamespace, mysql.ChPodNSCloudTags, CloudTagsKey](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNamespaceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.CloudTags.IsDifferent() {
		bytes, err := json.Marshal(fieldsUpdate.CloudTags.GetNew())
		if err != nil {
			log.Error(err)
			return
		}
		updateInfo["cloud_tags"] = string(bytes)
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodNSCloudTags
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]CloudTagsKey{{ID: sourceID}},
				[]mysql.ChPodNSCloudTags{{ID: sourceID, CloudTags: updateInfo["cloud_tags"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, CloudTagsKey{ID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) sourceToTarget(md *message.Metadata, item *mysql.PodNamespace) (keys []CloudTagsKey, targets []mysql.ChPodNSCloudTags) {
	if len(item.CloudTags) == 0 {
		return
	}
	bytes, err := json.Marshal(item.CloudTags)
	if err != nil {
		log.Error(err)
		return
	}
	return []CloudTagsKey{{ID: item.ID}}, []mysql.ChPodNSCloudTags{{ID: item.ID, CloudTags: string(bytes), TeamID: md.TeamID, DomainID: md.DomainID}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) softDeletedTargetsUpdated(targets []mysql.ChPodNSCloudTags, db *mysql.DB) {

}
