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

type ChChostCloudTags struct {
	SubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChChostCloudTags, CloudTagsKey]
}

func NewChChostCloudTags() *ChChostCloudTags {
	mng := &ChChostCloudTags{
		newSubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChChostCloudTags, CloudTagsKey](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_VM_CLOUD_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate) {
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
		var chItem mysql.ChChostCloudTags
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]CloudTagsKey{{ID: sourceID}},
				[]mysql.ChChostCloudTags{{ID: sourceID, CloudTags: updateInfo["cloud_tags"].(string)}},
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, CloudTagsKey{ID: sourceID})
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) sourceToTarget(item *mysql.VM) (keys []CloudTagsKey, targets []mysql.ChChostCloudTags) {
	if len(item.CloudTags) == 0 {
		return
	}
	bytes, err := json.Marshal(item.CloudTags)
	if err != nil {
		log.Error(err)
		return
	}
	return []CloudTagsKey{{ID: item.ID}}, []mysql.ChChostCloudTags{{ID: item.ID, CloudTags: string(bytes)}}
}
