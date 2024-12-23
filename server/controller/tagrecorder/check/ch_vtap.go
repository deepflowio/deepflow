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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChVTap struct {
	UpdaterBase[metadbmodel.ChVTap, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVTap(resourceTypeToIconID map[IconKey]int) *ChVTap {
	updater := &ChVTap{
		UpdaterBase[metadbmodel.ChVTap, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VTAP,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (v *ChVTap) generateNewData() (map[IDKey]metadbmodel.ChVTap, bool) {
	var vTaps []metadbmodel.VTap
	err := metadb.DefaultDB.Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChVTap)
	for _, vTap := range vTaps {
		keyToItem[IDKey{ID: vTap.ID}] = metadbmodel.ChVTap{
			ID:   vTap.ID,
			Name: vTap.Name,
			Type: vTap.Type,
		}
	}
	return keyToItem, true
}

func (v *ChVTap) generateKey(dbItem metadbmodel.ChVTap) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (v *ChVTap) generateUpdateInfo(oldItem, newItem metadbmodel.ChVTap) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.Type != newItem.Type {
		updateInfo["type"] = newItem.Type
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
