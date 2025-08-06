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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type ChChostCloudTags struct {
	SubscriberComponent[
		*message.VMAdd,
		message.VMAdd,
		*message.VMUpdate,
		message.VMUpdate,
		*message.VMDelete,
		message.VMDelete,
		metadbmodel.VM,
		metadbmodel.ChChostCloudTags,
		IDKey,
	]
}

func NewChChostCloudTags() *ChChostCloudTags {
	mng := &ChChostCloudTags{
		newSubscriberComponent[
			*message.VMAdd,
			message.VMAdd,
			*message.VMUpdate,
			message.VMUpdate,
			*message.VMDelete,
			message.VMDelete,
			metadbmodel.VM,
			metadbmodel.ChChostCloudTags,
			IDKey,
		](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) onResourceUpdated(md *message.Metadata, updateMessage *message.VMUpdate) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.VMFieldsUpdate)
	newSource := updateMessage.GetNewMetadbItem().(*metadbmodel.VM)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if !fieldsUpdate.LearnedCloudTags.IsDifferent() && !fieldsUpdate.CustomCloudTags.IsDifferent() {
		return
	}

	cloudTagMap := MergeCloudTags(newSource.LearnedCloudTags, newSource.CustomCloudTags)
	bytes, err := json.Marshal(cloudTagMap)
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return
	}
	updateInfo["cloud_tags"] = string(bytes)
	targetKey := IDKey{ID: sourceID}
	var chItem metadbmodel.ChChostCloudTags
	db.Where("id = ?", sourceID).Find(&chItem)
	if chItem.ID == 0 {
		c.SubscriberComponent.dbOperator.add(
			[]IDKey{targetKey},
			[]metadbmodel.ChChostCloudTags{{
				ChIDBase:  metadbmodel.ChIDBase{ID: sourceID},
				CloudTags: updateInfo["cloud_tags"].(string),
				TeamID:    md.GetTeamID(),
				DomainID:  md.GetDomainID(),
			}},
			db,
		)
		return
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) sourceToTarget(md *message.Metadata, source *metadbmodel.VM) (keys []IDKey, targets []metadbmodel.ChChostCloudTags) {
	cloudTagMap := MergeCloudTags(source.LearnedCloudTags, source.CustomCloudTags)
	if len(cloudTagMap) == 0 {
		return
	}
	bytes, err := json.Marshal(cloudTagMap)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(md.GetORGID()))
		return
	}
	return []IDKey{{ID: source.ID}}, []metadbmodel.ChChostCloudTags{{
		ChIDBase:  metadbmodel.ChIDBase{ID: source.ID},
		CloudTags: string(bytes),
		TeamID:    md.GetTeamID(),
		DomainID:  md.GetDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) softDeletedTargetsUpdated(targets []metadbmodel.ChChostCloudTags, db *metadb.DB) {

}
