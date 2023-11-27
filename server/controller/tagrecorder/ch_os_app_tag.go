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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
)

type ChOSAppTag struct {
	UpdaterComponent[mysql.ChOSAppTag, OSAPPTagKey]
}

func NewChOSAppTag() *ChOSAppTag {
	updater := &ChOSAppTag{
		newUpdaterComponent[mysql.ChOSAppTag, OSAPPTagKey](
			RESOURCE_TYPE_CH_OS_APP_TAG,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (o *ChOSAppTag) generateNewData() (map[OSAPPTagKey]mysql.ChOSAppTag, bool) {
	processes, err := query.FindInBatches[mysql.Process](mysql.Db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(o.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[OSAPPTagKey]mysql.ChOSAppTag)
	for _, process := range processes {
		splitTags := strings.Split(process.OSAPPTags, ", ")
		for _, singleTag := range splitTags {
			splitSingleTag := strings.Split(singleTag, ":")
			if len(splitSingleTag) == 2 {
				key := OSAPPTagKey{
					PID: process.ID,
					Key: strings.Trim(splitSingleTag[0], " "),
				}
				keyToItem[key] = mysql.ChOSAppTag{
					PID:   process.ID,
					Key:   strings.Trim(splitSingleTag[0], " "),
					Value: strings.Trim(splitSingleTag[1], " "),
				}
			}
		}
	}
	return keyToItem, true
}

func (o *ChOSAppTag) generateKey(dbItem mysql.ChOSAppTag) OSAPPTagKey {
	return OSAPPTagKey{PID: dbItem.PID, Key: dbItem.Key}
}

func (o *ChOSAppTag) generateUpdateInfo(oldItem, newItem mysql.ChOSAppTag) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
