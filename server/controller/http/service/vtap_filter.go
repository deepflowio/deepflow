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
	"fmt"
	"net/http"
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/gin-gonic/gin"
)

type UserInfo struct {
	Type         int
	ID           int
	ORGID        int
	DatabaseName string
}

func GetUserInfo(c *gin.Context) *UserInfo {
	orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
	userType, _ := c.Get(common.HEADER_KEY_X_USER_TYPE)
	userID, _ := c.Get(common.HEADER_KEY_X_USER_ID)
	return &UserInfo{
		Type:  userType.(int),
		ID:    userID.(int),
		ORGID: orgID.(int),
	}
}

func GetUnauthorizedTeamIDs(userInfo *UserInfo, fpermitCfg *common.FPermit) (map[int]struct{}, error) {
	if !fpermitCfg.Enabled {
		return nil, nil
	}

	body := make(map[string]interface{})
	response, err := common.CURLPerform(
		http.MethodGet,
		fmt.Sprintf(
			"http://%s:%d/v1/org/%d/scope_teams?reverse=true",
			fpermitCfg.Host, fpermitCfg.Port, userInfo.ORGID,
		),
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
		common.WithHeader(common.HEADER_KEY_X_ORG_ID, fmt.Sprintf("%d", userInfo.ORGID)),
	)
	if err != nil {
		return nil, err
	}

	teamIDMap := make(map[int]struct{}, 0)
	for k, _ := range response.Get("DATA").MustMap() {
		tid, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", k, err.Error())
		}
		teamIDMap[tid] = struct{}{}

	}
	log.Debugf("unauthorized team ids: %#v", teamIDMap)
	return teamIDMap, nil
}

func getAgentByUser(userInfo *UserInfo, fpermitCfg *common.FPermit, vtaps []mysql.VTap) ([]mysql.VTap, error) {
	if userInfo.Type == common.DEFAULT_USER_TYPE && userInfo.ID == common.DEFAULT_USER_ID {
		return vtaps, nil
	}
	teamIDMap, err := GetUnauthorizedTeamIDs(userInfo, fpermitCfg)
	if err != nil {
		return nil, err
	}

	var results []mysql.VTap
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

func getAgentGroupByUser(userInfo *UserInfo, fpermitCfg *common.FPermit, vtapGroups []*mysql.VTapGroup) ([]*mysql.VTapGroup, error) {
	if userInfo.Type == common.DEFAULT_USER_TYPE && userInfo.ID == common.DEFAULT_USER_ID {
		return vtapGroups, nil
	}
	teamIDMap, err := GetUnauthorizedTeamIDs(userInfo, fpermitCfg)
	if err != nil {
		return nil, err
	}

	var results []*mysql.VTapGroup
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
