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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChOSAppTags struct {
	SubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChOSAppTags, OSAPPTagsKey]
}

func NewChOSAppTags() *ChOSAppTags {
	mng := &ChOSAppTags{
		newSubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChOSAppTags, OSAPPTagsKey](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_OS_APP_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.OSAPPTags.IsDifferent() {
		osAppTagsMap := map[string]string{}
		splitTags := strings.Split(fieldsUpdate.OSAPPTags.GetNew(), ", ")

		for _, splitTag := range splitTags {
			splitSingleTag := strings.Split(splitTag, ":")
			if len(splitSingleTag) == 2 {
				osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		bytes, err := json.Marshal(osAppTagsMap)
		if err != nil {
			log.Error(err)
			return
		}
		updateInfo["os_app_tags"] = string(bytes)
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChOSAppTags
		db.Where("pid = ?", sourceID).First(&chItem)
		if chItem.PID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]OSAPPTagsKey{{PID: sourceID}},
				[]mysql.ChOSAppTags{{PID: sourceID, OSAPPTags: updateInfo["os_app_tags"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, OSAPPTagsKey{PID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) sourceToTarget(md *message.Metadata, item *mysql.Process) (keys []OSAPPTagsKey, targets []mysql.ChOSAppTags) {
	if item.OSAPPTags == "" {
		return
	}
	osAppTagsMap := map[string]string{}
	splitTags := strings.Split(item.OSAPPTags, ", ")

	for _, splitTag := range splitTags {
		splitSingleTag := strings.Split(splitTag, ":")
		if len(splitSingleTag) == 2 {
			osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
		}
	}
	bytes, err := json.Marshal(osAppTagsMap)
	if err != nil {
		log.Error(err)
		return
	}
	return []OSAPPTagsKey{{PID: item.ID}}, []mysql.ChOSAppTags{{PID: item.ID, OSAPPTags: string(bytes), TeamID: md.TeamID, DomainID: md.DomainID}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) softDeletedTargetsUpdated(targets []mysql.ChOSAppTags, db *mysql.DB) {

}
