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

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChOSAppTag struct {
	UpdaterBase[mysqlmodel.ChOSAppTag, OSAPPTagKey]
}

func NewChOSAppTag() *ChOSAppTag {
	updater := &ChOSAppTag{
		UpdaterBase[mysqlmodel.ChOSAppTag, OSAPPTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_OS_APP_TAG,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (o *ChOSAppTag) generateNewData() (map[OSAPPTagKey]mysqlmodel.ChOSAppTag, bool) {
	processes, err := query.FindInBatches[mysqlmodel.Process](o.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(o.resourceTypeName, err), o.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[OSAPPTagKey]mysqlmodel.ChOSAppTag)
	for _, process := range processes {
		teamID, err := tagrecorder.GetTeamID(process.Domain, process.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", o.resourceTypeName, err.Error(), process, o.db.LogPrefixORGID)
		}

		splitTags := strings.Split(process.OSAPPTags, ", ")
		for _, singleTag := range splitTags {
			splitSingleTag := strings.SplitN(singleTag, ":", 2)
			if len(splitSingleTag) == 2 {
				key := OSAPPTagKey{
					PID: process.ID,
					Key: strings.Trim(splitSingleTag[0], " "),
				}
				keyToItem[key] = mysqlmodel.ChOSAppTag{
					PID:         process.ID,
					Key:         strings.Trim(splitSingleTag[0], " "),
					Value:       strings.Trim(splitSingleTag[1], " "),
					TeamID:      teamID,
					DomainID:    tagrecorder.DomainToDomainID[process.Domain],
					SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
				}
			}
		}
	}
	return keyToItem, true
}

func (o *ChOSAppTag) generateKey(dbItem mysqlmodel.ChOSAppTag) OSAPPTagKey {
	return OSAPPTagKey{PID: dbItem.PID, Key: dbItem.Key}
}

func (o *ChOSAppTag) generateUpdateInfo(oldItem, newItem mysqlmodel.ChOSAppTag) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
