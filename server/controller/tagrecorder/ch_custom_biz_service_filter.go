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

type ChCustomBizServiceFilter struct {
	UpdaterComponent[metadbmodel.ChCustomBizServiceFilter, IDKey]
}

func NewChCustomBizServiceFilter() *ChCustomBizServiceFilter {
	updater := &ChCustomBizServiceFilter{
		newUpdaterComponent[metadbmodel.ChCustomBizServiceFilter, IDKey](
			RESOURCE_TYPE_CH_CUSTOM_BIZ_SERVICE_FILTER,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (s *ChCustomBizServiceFilter) generateNewData(db *metadb.DB) (map[IDKey]metadbmodel.ChCustomBizServiceFilter, bool) {
	log.Infof("generate data for %s", s.resourceTypeName, db.LogPrefixORGID)
	// TODO 从前端 API 获得
	keyToItem := make(map[IDKey]metadbmodel.ChCustomBizServiceFilter)
	keyToItem[IDKey{ID: 1}] = metadbmodel.ChCustomBizServiceFilter{
		ID:           1,
		ClientFilter: "pod_id_0=1",
		ServerFilter: "pod_id_1=2",
	}
	return keyToItem, true
}

func (s *ChCustomBizServiceFilter) generateKey(dbItem metadbmodel.ChCustomBizServiceFilter) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (s *ChCustomBizServiceFilter) generateUpdateInfo(oldItem, newItem metadbmodel.ChCustomBizServiceFilter) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.ClientFilter != newItem.ClientFilter {
		updateInfo["client_filter"] = newItem.ClientFilter
	}
	if oldItem.ServerFilter != newItem.ServerFilter {
		updateInfo["server_filter"] = newItem.ServerFilter
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
