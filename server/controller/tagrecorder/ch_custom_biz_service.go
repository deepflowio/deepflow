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

type ChCustomBizService struct {
	UpdaterComponent[metadbmodel.ChCustomBizService, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChCustomBizService(resourceTypeToIconID map[IconKey]int) *ChCustomBizService {
	updater := &ChCustomBizService{
		newUpdaterComponent[metadbmodel.ChCustomBizService, IDKey](
			RESOURCE_TYPE_CH_CUSTOM_BIZ_SERVICE,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (s *ChCustomBizService) generateNewData(db *metadb.DB) (map[IDKey]metadbmodel.ChCustomBizService, bool) {
	log.Infof("generate data for %s", s.resourceTypeName, db.LogPrefixORGID)
	// TODO 从前端 API 获得
	iconID := s.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_CUSTOM_BIZ_SERVICE}]
	keyToItem := make(map[IDKey]metadbmodel.ChCustomBizService)
	keyToItem[IDKey{ID: 1}] = metadbmodel.ChCustomBizService{
		ID:     1,
		Name:   "test_cus_biz_svc",
		UID:    "",
		IconID: iconID,
		TeamID: 1,
	}
	return keyToItem, true
}

func (s *ChCustomBizService) generateKey(dbItem metadbmodel.ChCustomBizService) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (s *ChCustomBizService) generateUpdateInfo(oldItem, newItem metadbmodel.ChCustomBizService) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
