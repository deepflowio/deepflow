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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChOSAppTags struct {
	UpdaterBase[metadbmodel.ChOSAppTags, OSAPPTagsKey]
}

func NewChOSAppTags() *ChOSAppTags {
	updater := &ChOSAppTags{
		UpdaterBase[metadbmodel.ChOSAppTags, OSAPPTagsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_OS_APP_TAGS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (o *ChOSAppTags) generateNewData() (map[OSAPPTagsKey]metadbmodel.ChOSAppTags, bool) {
	processes, err := query.FindInBatches[metadbmodel.Process](o.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(o.resourceTypeName, err), o.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[OSAPPTagsKey]metadbmodel.ChOSAppTags)
	for _, process := range processes {
		teamID, err := tagrecorder.GetTeamID(process.Domain, process.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", o.resourceTypeName, err.Error(), process, o.db.LogPrefixORGID)
		}

		osAppTagsMap := map[string]string{}
		splitOsAppTags := strings.Split(process.OSAPPTags, ", ")
		for _, singleOsAppTag := range splitOsAppTags {
			splitSingleTag := strings.SplitN(singleOsAppTag, ":", 2)
			if len(splitSingleTag) == 2 {
				osAppTagsMap[strings.Trim(splitSingleTag[0], " ")] = strings.Trim(splitSingleTag[1], " ")
			}
		}
		if len(osAppTagsMap) > 0 {
			osAppTagsStr, err := json.Marshal(osAppTagsMap)
			if err != nil {
				log.Error(err, o.db.LogPrefixORGID)
				return nil, false
			}
			key := OSAPPTagsKey{
				PID: process.ID,
			}
			keyToItem[key] = metadbmodel.ChOSAppTags{
				PID:         process.ID,
				OSAPPTags:   string(osAppTagsStr),
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[process.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (o *ChOSAppTags) generateKey(dbItem metadbmodel.ChOSAppTags) OSAPPTagsKey {
	return OSAPPTagsKey{PID: dbItem.PID}
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
