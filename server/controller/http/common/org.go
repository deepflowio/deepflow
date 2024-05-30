/**
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

package common

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
)

var log = logging.MustGetLogger("service.common")

type UserInfo struct {
	Type         int
	ID           int
	ORGID        int
	DatabaseName string
}

func NewUserInfo(userType, userID, orgID int) *UserInfo {
	return &UserInfo{
		Type:  userType,
		ID:    userID,
		ORGID: orgID,
	}
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
