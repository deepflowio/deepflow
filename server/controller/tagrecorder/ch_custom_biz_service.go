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
	bizRes, err := common.CURLPerform(
		"GET",
		fmt.Sprintf("http://%s:%d/v1/biz/all_svcs", s.cfg.DFWebService.Host, s.cfg.DFWebService.Port),
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", common.USER_TYPE_SUPER_ADMIN)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", common.USER_ID_SUPER_ADMIN)),
		common.WithHeader(common.HEADER_KEY_X_ORG_ID, fmt.Sprintf("%d", db.ORGID)),
	)
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return nil, false
	}
	for i, _ := range bizRes.Get("DATA").MustArray() {
		bizData := bizRes.Get("DATA").GetIndex(i)
		bizName := bizData.Get("NAME").MustString()
		bizType := bizData.Get("TYPE").MustInt()
		teamID := bizData.Get("team_id").MustInt()
		if bizType != CUSTOM_BIZ_SERVICE_TYPE {
			continue
		}
		for j, _ := range bizData.Get("svcs").MustArray() {
			serviceData := bizData.Get("svcs").GetIndex(j)
			serviceID := serviceData.Get("ID").MustInt()
			iconID := serviceData.Get("ICON_ID").MustInt()
			serviceName := serviceData.Get("NAME").MustString()
			keyToItem[IDKey{ID: serviceID}] = metadbmodel.ChCustomBizService{
				ID:     serviceID,
				Name:   fmt.Sprintf("%s/%s", bizName, serviceName),
				UID:    "",
				IconID: iconID,
				TeamID: teamID,
			}
		}
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
