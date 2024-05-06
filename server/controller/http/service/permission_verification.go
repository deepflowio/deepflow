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

package service

import (
	"fmt"
	"net/http"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

type PermitVerifyMethod string

const (
	PermitVerifyAdd    PermitVerifyMethod = "add"
	PermitVerifyUpdate PermitVerifyMethod = "update"
	PermitVerifyDelete PermitVerifyMethod = "delete"
)

func isPermitted(fpermit config.FPermit, userInfo *UserInfo, m PermitVerifyMethod, teamID int) error {
	if !fpermit.Enabled {
		return nil
	}

	body := make(map[string]interface{})
	response, err := common.CURLPerform(
		http.MethodGet,
		fmt.Sprintf(
			"http://%s:%d/v1/org/%d/permit_verify?method=%s&team_id=%d",
			fpermit.Host, fpermit.Port, userInfo.ORGID, m, teamID,
		),
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
	)
	if err != nil {
		return err
	}
	result, err := response.Get("DATA").Bool()
	if err != nil {
		return err
	}
	if result == false {
		if des := response.Get("DESCRIPTION").MustString(); des != "" {
			fmt.Errorf("%w %s", httpcommon.ERR_NO_PERMISSIONS, des)
		}
		return fmt.Errorf("%w", httpcommon.ERR_NO_PERMISSIONS)
	}
	return nil
}

func IsAddPermitted(fpermit config.FPermit, userInfo *UserInfo, teamID int) error {
	return isPermitted(fpermit, userInfo, PermitVerifyAdd, teamID)
}

func IsUpdatePermitted(fpermit config.FPermit, userInfo *UserInfo, teamID int) error {
	return isPermitted(fpermit, userInfo, PermitVerifyUpdate, teamID)
}

func IsDeletePermitted(fpermit config.FPermit, userInfo *UserInfo, teamID int) error {
	return isPermitted(fpermit, userInfo, PermitVerifyDelete, teamID)
}
