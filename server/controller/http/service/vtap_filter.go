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

package service

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

func GetAgentByUser(userInfo *httpcommon.UserInfo, fpermitCfg *common.FPermit, vtaps []mysqlmodel.VTap) ([]mysqlmodel.VTap, error) {
	if userInfo.Type == common.DEFAULT_USER_TYPE && userInfo.ID == common.DEFAULT_USER_ID {
		return vtaps, nil
	}
	teamIDMap, err := httpcommon.GetUnauthorizedTeamIDs(userInfo, fpermitCfg)
	if err != nil {
		return nil, err
	}

	var results []mysqlmodel.VTap
	for _, vtap := range vtaps {
		if fpermitCfg.Enabled {
			if _, ok := teamIDMap[vtap.TeamID]; !ok {
				results = append(results, vtap)
			}
			continue
		}

		if vtap.TeamID == common.DEFAULT_TEAM_ID {
			results = append(results, vtap)
		}
	}
	return results, nil
}

func GetAgentGroupByUser(userInfo *httpcommon.UserInfo, fpermitCfg *common.FPermit, vtapGroups []*mysqlmodel.VTapGroup) ([]*mysqlmodel.VTapGroup, error) {
	if userInfo.Type == common.DEFAULT_USER_TYPE && userInfo.ID == common.DEFAULT_USER_ID {
		return vtapGroups, nil
	}
	teamIDMap, err := httpcommon.GetUnauthorizedTeamIDs(userInfo, fpermitCfg)
	if err != nil {
		return nil, err
	}

	var results []*mysqlmodel.VTapGroup
	for _, vtapGroup := range vtapGroups {
		if fpermitCfg.Enabled {
			if _, ok := teamIDMap[vtapGroup.TeamID]; !ok {
				results = append(results, vtapGroup)
			}
			continue
		}

		if vtapGroup.TeamID == common.DEFAULT_TEAM_ID {
			results = append(results, vtapGroup)
		}
	}
	return results, nil
}
