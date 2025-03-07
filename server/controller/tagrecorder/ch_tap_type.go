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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChTapType struct {
	UpdaterComponent[metadbmodel.ChTapType, TapTypeKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChTapType(resourceTypeToIconID map[IconKey]int) *ChTapType {
	updater := &ChTapType{
		newUpdaterComponent[metadbmodel.ChTapType, TapTypeKey](
			RESOURCE_TYPE_TAP_TYPE,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (t *ChTapType) generateNewData(db *metadb.DB) (map[TapTypeKey]metadbmodel.ChTapType, bool) {
	var tapTypes []metadbmodel.TapType
	err := db.Unscoped().Find(&tapTypes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(t.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[TapTypeKey]metadbmodel.ChTapType)
	for _, tapType := range tapTypes {
		keyToItem[TapTypeKey{Value: tapType.Value}] = metadbmodel.ChTapType{
			Value: tapType.Value,
			Name:  tapType.Name,
		}
	}
	return keyToItem, true
}

func (t *ChTapType) generateKey(dbItem metadbmodel.ChTapType) TapTypeKey {
	return TapTypeKey{Value: dbItem.Value}
}

func (t *ChTapType) generateUpdateInfo(oldItem, newItem metadbmodel.ChTapType) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
