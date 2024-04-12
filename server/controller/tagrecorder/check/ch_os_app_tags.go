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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
)

type ChOSAppTags struct {
	UpdaterBase[mysql.ChOSAppTags, OSAPPTagsKey]
}

func NewChOSAppTags() *ChOSAppTags {
	updater := &ChOSAppTags{
		UpdaterBase[mysql.ChOSAppTags, OSAPPTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_OS_APP_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (o *ChOSAppTags) generateNewData() (map[OSAPPTagsKey]mysql.ChOSAppTags, bool) {
	processes, err := query.FindInBatches[mysql.Process](o.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(o.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[OSAPPTagsKey]mysql.ChOSAppTags)
	for _, process := range processes {
		osAppTagsMap := map[string]string{}
		splitOsAppTags := strings.Split(process.OSAPPTags, ", ")
		for _, singleOsAppTag := range splitOsAppTags {
			splitSingleTag := strings.Split(singleOsAppTag, ":")
			if len(splitSingleTag) == 2 {
				osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		if len(osAppTagsMap) > 0 {
			osAppTagsStr, err := json.Marshal(osAppTagsMap)
			if err != nil {
				log.Error(err)
				return nil, false
			}
			key := OSAPPTagsKey{
				PID: process.ID,
			}
			keyToItem[key] = mysql.ChOSAppTags{
				PID:       process.ID,
				OSAPPTags: string(osAppTagsStr),
			}
		}
	}
	return keyToItem, true
}

func (o *ChOSAppTags) generateKey(dbItem mysql.ChOSAppTags) OSAPPTagsKey {
	return OSAPPTagsKey{PID: dbItem.PID}
}

func (o *ChOSAppTags) generateUpdateInfo(oldItem, newItem mysql.ChOSAppTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.OSAPPTags != newItem.OSAPPTags {
		updateInfo["os_app_tags"] = newItem.OSAPPTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
