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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/common"
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
	keyToItem := make(map[IDKey]metadbmodel.ChCustomBizService)
	if !s.cfg.DFWebService.Enabled {
		return keyToItem, true
	}
	body := make(map[string]interface{})
	bizRes, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/biz", cfg.DFWebService.Host, cfg.DFWebService.Port), body)
	if err != nil {
		log.Error(err)
		return nil, false
	}
	for i, _ := range bizRes.Get("DATA").MustArray() {
		bizData := bizRes.Get("DATA").GetIndex(i)
		bizLcuuid := bizData.Get("LCUUID").MustString()
		serviceRes, err = common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/biz/%s", cfg.DFWebService.Host, cfg.DFWebService.Port, bizLcuuid), body)
		for i, _ := range serviceRes.Get("DATA").MustArray() {
			serviceData := serviceRes.Get("DATA").GetIndex(i)
			serviceID := 1
		}

		if data.Get("NODE_TYPE").MustString() == "" || data.Get("ID").MustInt() == 0 {
			continue
		}
		resourceType, ok := DBNodeTypeToResourceType[data.Get("NODE_TYPE").MustString()]
		if !ok {
			continue
		}
		key := IconKey{
			NodeType: resourceType,
			SubType:  data.Get("SUB_TYPE").MustInt(),
		}
		resourceToIconID[key] = data.Get("ID").MustInt()

	}
	iconID := s.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_CUSTOM_BIZ_SERVICE}]

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
