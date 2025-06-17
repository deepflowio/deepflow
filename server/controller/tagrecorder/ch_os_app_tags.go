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
	"slices"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChOSAppTags struct {
	SubscriberComponent[
		*message.ProcessAdd,
		message.ProcessAdd,
		*message.ProcessFieldsUpdate,
		message.ProcessFieldsUpdate,
		*message.ProcessDelete,
		message.ProcessDelete,
		metadbmodel.Process,
		metadbmodel.ChOSAppTags,
		IDKey,
	]
}

func NewChOSAppTags() *ChOSAppTags {
	mng := &ChOSAppTags{
		newSubscriberComponent[
			*message.ProcessAdd,
			message.ProcessAdd,
			*message.ProcessFieldsUpdate,
			message.ProcessFieldsUpdate,
			*message.ProcessDelete,
			message.ProcessDelete,
			metadbmodel.Process,
			metadbmodel.ChOSAppTags,
			IDKey,
		](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_OS_APP_TAGS,
		),
	}
	mng.subscriberDG = mng
	mng.hookers[hookerDeletePage] = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate, db *metadb.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.OSAPPTags.IsDifferent() {
		osAppTags, _ := common.StrToJsonAndMap(fieldsUpdate.OSAPPTags.GetNew())
		if osAppTags != "" {
			updateInfo["os_app_tags"] = osAppTags
		}
	}
	gid := int(fieldsUpdate.GID.GetNew())
	targetKey := IDKey{ID: gid}
	if len(updateInfo) > 0 {
		var chItem metadbmodel.ChOSAppTags
		db.Where("id = ?", gid).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]IDKey{targetKey},
				[]metadbmodel.ChOSAppTags{{ChIDBase: metadbmodel.ChIDBase{ID: gid}, OSAPPTags: updateInfo["os_app_tags"].(string)}},
				db,
			)
		}
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) sourceToTarget(md *message.Metadata, source *metadbmodel.Process) (keys []IDKey, targets []metadbmodel.ChOSAppTags) {
	if source.OSAPPTags == "" {
		return
	}
	gid := int(source.GID)
	osAppTags, _ := common.StrToJsonAndMap(source.OSAPPTags)
	return []IDKey{{ID: gid}}, []metadbmodel.ChOSAppTags{{
		ChIDBase:    metadbmodel.ChIDBase{ID: gid},
		OSAPPTags:   osAppTags,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChOSAppTags) softDeletedTargetsUpdated(targets []metadbmodel.ChOSAppTags, db *metadb.DB) {

}

func (c *ChOSAppTags) beforeDeletePage(dbData []*metadbmodel.Process, msg *message.ProcessDelete) []*metadbmodel.Process {
	gids := msg.GetAddition().(*message.ProcessDeleteAddition).DeletedGIDs
	newDatas := []*metadbmodel.Process{}
	for _, item := range dbData {
		if slices.Contains(gids, item.GID) {
			newDatas = append(newDatas, item)
		}
	}
	return newDatas
}
