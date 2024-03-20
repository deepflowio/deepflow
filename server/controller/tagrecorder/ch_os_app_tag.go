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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChOSAppTag struct {
	SubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChOSAppTag, OSAPPTagKey]
}

func NewChOSAppTag() *ChOSAppTag {
	mng := &ChOSAppTag{
		newSubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChOSAppTag, OSAPPTagKey](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_OS_APP_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate) {
	keysToAdd := make([]OSAPPTagKey, 0)
	targetsToAdd := make([]mysql.ChOSAppTag, 0)
	keysToDelete := make([]OSAPPTagKey, 0)
	targetsToDelete := make([]mysql.ChOSAppTag, 0)
	var chItem mysql.ChOSAppTag
	var updateKey OSAPPTagKey
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.OSAPPTags.IsDifferent() {
		new := map[string]string{}
		old := map[string]string{}
		newStr := fieldsUpdate.OSAPPTags.GetNew()
		oldStr := fieldsUpdate.OSAPPTags.GetOld()
		splitNews := strings.Split(newStr, ", ")
		splitOlds := strings.Split(oldStr, ", ")

		for _, splitNew := range splitNews {
			splitSingleTag := strings.Split(splitNew, ":")
			if len(splitSingleTag) == 2 {
				new[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		for _, splitOld := range splitOlds {
			splitSingleTag := strings.Split(splitOld, ":")
			if len(splitSingleTag) == 2 {
				old[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		for k, v := range new {
			oldV, ok := old[k]
			if !ok {
				keysToAdd = append(keysToAdd, OSAPPTagKey{PID: sourceID, Key: k})
				targetsToAdd = append(targetsToAdd, mysql.ChOSAppTag{
					PID:   sourceID,
					Key:   k,
					Value: v,
				})
			} else {
				if oldV != v {
					updateKey = OSAPPTagKey{PID: sourceID, Key: k}
					updateInfo[k] = v
					mysql.Db.Where("pid = ? and `key` = ?", sourceID, k).First(&chItem) // TODO common
					if chItem.PID == 0 {
						keysToAdd = append(keysToAdd, OSAPPTagKey{PID: sourceID, Key: k})
						targetsToAdd = append(targetsToAdd, mysql.ChOSAppTag{
							PID:   sourceID,
							Key:   k,
							Value: v,
						})
					} else if len(updateInfo) > 0 {
						c.SubscriberComponent.dbOperator.update(chItem, updateInfo, updateKey)
					}
				}
			}
		}
		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, OSAPPTagKey{PID: sourceID, Key: k})
				targetsToDelete = append(targetsToDelete, mysql.ChOSAppTag{
					PID: sourceID,
					Key: k,
				})
			}
		}
	}
	if len(keysToAdd) > 0 {
		c.SubscriberComponent.dbOperator.add(keysToAdd, targetsToAdd)
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) sourceToTarget(source *mysql.Process) (keys []OSAPPTagKey, targets []mysql.ChOSAppTag) {
	osAppTagsMap := map[string]string{}
	splitTags := strings.Split(source.OSAPPTags, ", ")

	for _, splitTag := range splitTags {
		splitSingleTag := strings.Split(splitTag, ":")
		if len(splitSingleTag) == 2 {
			osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
		}
	}
	for k, v := range osAppTagsMap {
		keys = append(keys, OSAPPTagKey{PID: source.ID, Key: k})
		targets = append(targets, mysql.ChOSAppTag{
			PID:   source.ID,
			Key:   k,
			Value: v,
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChOSAppTag) softDeletedTargetsUpdated(targets []mysql.ChOSAppTag) {

}
