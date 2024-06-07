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
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

type AccessType string

const (
	AccessAdd    AccessType = "add"
	AccessUpdate AccessType = "update"
	AccessDelete AccessType = "delete"
)

var (
	urlPermitVerify = "http://%s:%d/v1/org/%d/permit_verify?method=%s"
	urlResource     = "http://%s:%d/v1/org/%d/resource"
)

type ResourceAccess struct {
	fpermit  common.FPermit
	userInfo *httpcommon.UserInfo
}

func NewResourceAccess(fpermit common.FPermit, userInfo *httpcommon.UserInfo) *ResourceAccess {
	return &ResourceAccess{
		fpermit:  fpermit,
		userInfo: userInfo,
	}
}

func (ra *ResourceAccess) CanAddResource(teamID int, resourceType, resourceUUID string) error {
	if !ra.fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID, AccessAdd)
	url += fmt.Sprintf("&team_id=%d", teamID)
	if err := PermitVerify(url, ra.userInfo, teamID); err != nil {
		return err
	}
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		return nil
	}

	url = fmt.Sprintf(urlResource, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID)
	body := map[string]interface{}{
		"team_id":       teamID,
		"owner_user_id": ra.userInfo.ID,
		"resource_type": resourceType,
		"resource_id":   resourceUUID,
	}
	return resourceVerify(url, http.MethodPost, ra.userInfo, teamID, body)
}

func (ra *ResourceAccess) CanUpdateResource(teamID int, resourceType, resourceUUID string, resourceUp map[string]interface{}) error {
	if !ra.fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID, AccessUpdate)
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		url += fmt.Sprintf("&team_id=%d&resource_type=%s", teamID, resourceType)
	} else {
		url += fmt.Sprintf("&resource_type=%s&resource_id=%s", resourceType, resourceUUID)
	}

	if err := PermitVerify(url, ra.userInfo, teamID); err != nil {
		return err
	}
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE ||
		resourceUp == nil || len(resourceUp) == 0 {
		return nil
	}

	url = fmt.Sprintf(urlResource, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID)
	body := map[string]interface{}{
		"resource_where": map[string]interface{}{
			"resource_type": resourceType,
			"resource_id":   resourceUUID,
		},
		"resource_up": resourceUp,
	}
	return resourceVerify(url, http.MethodPatch, ra.userInfo, teamID, body)
}

func (ra *ResourceAccess) CanDeleteResource(teamID int, resourceType, resourceUUID string) error {
	if !ra.fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID, AccessDelete)
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		url += fmt.Sprintf("&team_id=%d&resource_type=%s", teamID, resourceType)
	} else {
		url += fmt.Sprintf("&resource_type=%s&resource_id=%s", resourceType, resourceUUID)
	}

	if err := PermitVerify(url, ra.userInfo, teamID); err != nil {
		return err
	}
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		return nil
	}

	url = fmt.Sprintf(urlResource, ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID)
	body := map[string]interface{}{
		"resource_type": resourceType,
		"resource_ids":  resourceUUID,
	}
	return resourceVerify(url, http.MethodDelete, ra.userInfo, teamID, body)
}

func (ra *ResourceAccess) CanOperateDomainResource(teamID int, domainUUID string) error {
	if !ra.fpermit.Enabled {
		return nil
	}
	if (domainUUID == "" || domainUUID == common.DEFAULT_DOMAIN) &&
		ra.userInfo.Type != common.USER_TYPE_SUPER_ADMIN {
		return fmt.Errorf("non-super administrators do not have permission to operate")
	}

	url := fmt.Sprintf("http://%s:%d/v1/org/%d/permit_verify?method=update&resource_type=domain&resource_id=%s",
		ra.fpermit.Host, ra.fpermit.Port, ra.userInfo.ORGID, domainUUID)
	return PermitVerify(url, ra.userInfo, teamID)
}

func PermitVerify(url string, userInfo *httpcommon.UserInfo, teamID int) error {
	response, err := common.CURLPerform(
		http.MethodGet,
		url,
		make(map[string]interface{}),
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
	)
	if err != nil {
		return err
	}
	havePermission := response.Get("DATA").MustBool()

	if !havePermission {
		if desc := response.Get("DESCRIPTION").MustString(); desc != "" {
			log.Errorf("url(%s) user_type(%d) user_id(%d) team_id(%d) error: %s", url, userInfo.Type, userInfo.ID, teamID, desc)
			return fmt.Errorf("%w %s", httpcommon.ERR_NO_PERMISSIONS, desc)
		}
		log.Errorf("url(%s) user_type(%d) user_id(%d) team_id(%d)", url, userInfo.Type, userInfo.ID, teamID)
		return fmt.Errorf("%w", httpcommon.ERR_NO_PERMISSIONS)
	}
	return nil
}

func resourceVerify(url, httpMethod string, userInfo *httpcommon.UserInfo, teamID int, body map[string]interface{}) error {
	_, err := common.CURLPerform(
		httpMethod,
		url,
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
		common.WithHeader(common.HEADER_X_APP_KEY, common.DEFAULT_APP_KEY),
	)
	if err != nil {
		log.Errorf("url(%s) user_type(%d) user_id(%d) team_id(%d) body(%#v) error: %s",
			url, userInfo.Type, userInfo.ID, teamID, body, err.Error())
		return fmt.Errorf("%w %s", httpcommon.ERR_NO_PERMISSIONS, err.Error())
	}
	return nil
}
