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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChOSAppTags struct {
	SubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysqlmodel.Process, mysqlmodel.ChOSAppTags, OSAPPTagsKey]
}

func NewChOSAppTags() *ChOSAppTags {
	mng := &ChOSAppTags{
		newSubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysqlmodel.Process, mysqlmodel.ChOSAppTags, OSAPPTagsKey](
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
		osAppTags, _ := common.StrToJsonAndMap(fieldsUpdate.OSAPPTags.GetNew())
		if osAppTags != "" {
			updateInfo["os_app_tags"] = osAppTags
		}
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChOSAppTags
		db.Where("pid = ?", sourceID).First(&chItem)
		if chItem.PID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]OSAPPTagsKey{{PID: sourceID}},
				[]mysqlmodel.ChOSAppTags{{PID: sourceID, OSAPPTags: updateInfo["os_app_tags"].(string)}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, OSAPPTagsKey{PID: sourceID}, db)
		}
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) sourceToTarget(md *message.Metadata, item *mysqlmodel.Process) (keys []OSAPPTagsKey, targets []mysqlmodel.ChOSAppTags) {
	if item.OSAPPTags == "" {
		return
	}
	osAppTags, _ := common.StrToJsonAndMap(item.OSAPPTags)
	return []OSAPPTagsKey{{PID: item.ID}}, []mysqlmodel.ChOSAppTags{{
		PID:         item.ID,
		OSAPPTags:   osAppTags,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) softDeletedTargetsUpdated(targets []mysqlmodel.ChOSAppTags, db *mysql.DB) {

}
