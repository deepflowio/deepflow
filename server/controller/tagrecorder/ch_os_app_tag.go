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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChOSAppTag struct {
	SubscriberComponent[
		*message.ProcessAdd,
		message.ProcessAdd,
		*message.ProcessFieldsUpdate,
		message.ProcessFieldsUpdate,
		*message.ProcessDelete,
		message.ProcessDelete,
		metadbmodel.Process,
		metadbmodel.ChOSAppTag,
		OSAPPTagKey,
	]
}

func NewChOSAppTag() *ChOSAppTag {
	mng := &ChOSAppTag{
		newSubscriberComponent[
			*message.ProcessAdd,
			message.ProcessAdd,
			*message.ProcessFieldsUpdate,
			message.ProcessFieldsUpdate,
			*message.ProcessDelete,
			message.ProcessDelete,
			metadbmodel.Process,
			metadbmodel.ChOSAppTag,
			OSAPPTagKey,
		](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_OS_APP_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate, db *metadb.DB) {
	keysToAdd := make([]OSAPPTagKey, 0)
	targetsToAdd := make([]metadbmodel.ChOSAppTag, 0)
	keysToDelete := make([]OSAPPTagKey, 0)
	targetsToDelete := make([]metadbmodel.ChOSAppTag, 0)
	var chItem metadbmodel.ChOSAppTag
	var updateKey OSAPPTagKey
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.OSAPPTags.IsDifferent() {
		_, new := common.StrToJsonAndMap(fieldsUpdate.OSAPPTags.GetNew())
		_, old := common.StrToJsonAndMap(fieldsUpdate.OSAPPTags.GetOld())

		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, OSAPPTagKey{PID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, metadbmodel.ChOSAppTag{
					PID:   sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = OSAPPTagKey{PID: sourceID, Key: k}
					updateInfo["value"] = v
					db.Where("pid = ? and `key` = ?", sourceID, k).First(&chItem) // TODO common
					if chItem.PID == 0 {
						keysToAdd = append(keysToAdd, OSAPPTagKey{PID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, metadbmodel.ChOSAppTag{
							PID:   sourceID,
							Key:   k,
							Value: v,
						})
					} else if len(updateInfo) > 0 {
						c.SubscriberComponent.dbOperator.update(chItem, updateInfo, updateKey, db)
					}
				}
			}
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, OSAPPTagKey{PID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, metadbmodel.ChOSAppTag{
					PID: sourceID,
					Key: k,
				})
			}
		}
	}
	if len(keysToAdd) > 0 {
		c.SubscriberComponent.dbOperator.add(keysToAdd, targetsToAdd, db)
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete, db)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) sourceToTarget(md *message.Metadata, source *metadbmodel.Process) (keys []OSAPPTagKey, targets []metadbmodel.ChOSAppTag) {
	_, osAppTagsMap := common.StrToJsonAndMap(source.OSAPPTags)

	for k, v := range osAppTagsMap {
		keys = append(keys, OSAPPTagKey{PID: source.ID, Key: k})
		targets = append(targets, metadbmodel.ChOSAppTag{
			PID:         source.ID,
			Key:         k,
			Value:       v,
			TeamID:      md.TeamID,
			DomainID:    md.DomainID,
			SubDomainID: md.SubDomainID,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) softDeletedTargetsUpdated(targets []metadbmodel.ChOSAppTag, db *metadb.DB) {

}
