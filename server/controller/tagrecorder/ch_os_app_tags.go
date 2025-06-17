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

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChOSAppTags struct {
	UpdaterComponent[metadbmodel.ChOSAppTags, IDKey]
}

func NewChOSAppTags() *ChOSAppTags {
	updater := &ChOSAppTags{
		newUpdaterComponent[metadbmodel.ChOSAppTags, IDKey](
			RESOURCE_TYPE_CH_OS_APP_TAGS,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (o *ChOSAppTags) generateNewData(db *metadb.DB) (map[IDKey]metadbmodel.ChOSAppTags, bool) {
	var processes []metadbmodel.Process
	keyToItem := make(map[IDKey]metadbmodel.ChOSAppTags)
	gidToOsAppTagMap := make(map[int]map[string]string)

	err := db.Find(&processes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(o.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	for _, process := range processes {
		gid := int(process.GID)
		osAppTagsMap := map[string]string{}
		splitOsAppTags := strings.Split(process.OSAPPTags, ", ")
		for _, singleOsAppTag := range splitOsAppTags {
			splitSingleTag := strings.Split(singleOsAppTag, ":")
			if len(splitSingleTag) == 2 {
				osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		if len(osAppTagsMap) > 0 {
			osAppTagMap, ok := gidToOsAppTagMap[gid]
			if ok {
				for key, value := range osAppTagsMap {
					osAppTagMap[key] = value
				}
			} else {
				gidToOsAppTagMap[gid] = osAppTagsMap
			}
		}
	}

	for gid, osAppTagMap := range gidToOsAppTagMap {
		osAppTagsStr, err := json.Marshal(osAppTagMap)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		key := IDKey{
			ID: gid,
		}
		keyToItem[key] = metadbmodel.ChOSAppTags{
			ID:        gid,
			OSAPPTags: string(osAppTagsStr),
		}
	}

	return keyToItem, true
}

func (o *ChOSAppTags) generateKey(dbItem metadbmodel.ChOSAppTags) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (o *ChOSAppTags) generateUpdateInfo(oldItem, newItem metadbmodel.ChOSAppTags) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.OSAPPTags != newItem.OSAPPTags {
		updateInfo["os_app_tags"] = newItem.OSAPPTags
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
