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
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type AccessType string

const (
	AccessAdd    AccessType = "add"
	AccessUpdate AccessType = "update"
	AccessDelete AccessType = "delete"
)

var (
	urlPermitVerify  = "http://%s:%d/v1/org/%d/permit_verify?method=%s"
	urlResource      = "http://%s:%d/v1/org/%d/resource"
	urlUGCPermission = "http://%s:%d/v1/org/%d/ugc/permissions/patch"
)

type ResourceAccess struct {
	Fpermit  common.FPermit
	UserInfo *httpcommon.UserInfo
}

func NewResourceAccess(fpermit common.FPermit, userInfo *httpcommon.UserInfo) *ResourceAccess {
	return &ResourceAccess{
		Fpermit:  fpermit,
		UserInfo: userInfo,
	}
}

func (ra *ResourceAccess) CanAddResource(teamID int, resourceType, resourceUUID string) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessAdd)
	url += fmt.Sprintf("&team_id=%d", teamID)
	if err := PermitVerify(url, ra.UserInfo, teamID); err != nil {
		return err
	}
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		return nil
	}

	url = fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	body := map[string]interface{}{
		"team_id":       teamID,
		"owner_user_id": ra.UserInfo.ID,
		"resource_type": resourceType,
		"resource_id":   resourceUUID,
	}
	return resourceVerify(url, http.MethodPost, ra.UserInfo, teamID, body)
}

func (ra *ResourceAccess) CanUpdateResource(teamID int, resourceType, resourceUUID string, resourceUp map[string]interface{}) error {
	// Check if the current user has permission to operate on the current resource. This check can be skipped for super admin accounts.
	if ra.UserInfo.Type != common.USER_TYPE_SUPER_ADMIN {
		if !ra.Fpermit.Enabled {
			return nil
		}
		url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessUpdate)
		if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
			resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
			url += fmt.Sprintf("&team_id=%d&resource_type=%s", teamID, resourceType)
		} else {
			url += fmt.Sprintf("&resource_type=%s&resource_id=%s", resourceType, resourceUUID)
		}

		if err := PermitVerify(url, ra.UserInfo, teamID); err != nil {
			return err
		}
	}

	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE ||
		resourceUp == nil || len(resourceUp) == 0 {
		return nil
	}

	// When updating the owner or team of the current resource, the following check cannot be skipped even for super admins.
	if newOwnerID, ok := resourceUp["owner_user_id"]; ok {
		body := map[string]interface{}{
			"new_team_id":   teamID,
			"new_owner_id":  newOwnerID,
			"resource_type": resourceType,
			"resource_id":   resourceUUID,
		}
		url := fmt.Sprintf(urlUGCPermission, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
		if err := ugcPermission(url, ra.UserInfo, body); err != nil {
			return err
		}
	}

	url := fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	body := map[string]interface{}{
		"resource_where": map[string]interface{}{
			"resource_type": resourceType,
			"resource_id":   resourceUUID,
		},
		"resource_up": resourceUp,
	}
	return resourceVerify(url, http.MethodPatch, ra.UserInfo, teamID, body)
}

func (ra *ResourceAccess) CanDeleteResource(teamID int, resourceType, resourceUUID string) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessDelete)
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		url += fmt.Sprintf("&team_id=%d&resource_type=%s", teamID, resourceType)
	} else {
		url += fmt.Sprintf("&resource_type=%s&resource_id=%s", resourceType, resourceUUID)
	}

	if err := PermitVerify(url, ra.UserInfo, teamID); err != nil {
		return err
	}
	if resourceType == common.SET_RESOURCE_TYPE_AGENT ||
		resourceType == common.SET_RESOURCE_TYPE_DATA_SOURCE {
		return nil
	}

	url = fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	body := map[string]interface{}{
		"resource_type": resourceType,
		"resource_ids":  resourceUUID,
	}
	return resourceVerify(url, http.MethodDelete, ra.UserInfo, teamID, body)
}

func (ra *ResourceAccess) CanAddSubDomainResource(domainTeamID, subDomainTeamID int, resourceUUID string) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessAdd)
	url += fmt.Sprintf("&parent_team_id=%d&team_id=%d", domainTeamID, subDomainTeamID)
	if err := PermitVerify(url, ra.UserInfo, subDomainTeamID); err != nil {
		return err
	}

	url = fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	body := map[string]interface{}{
		"team_id":       subDomainTeamID,
		"owner_user_id": ra.UserInfo.ID,
		"resource_type": common.SET_RESOURCE_TYPE_SUB_DOMAIN,
		"resource_id":   resourceUUID,
	}
	return resourceVerify(url, http.MethodPost, ra.UserInfo, subDomainTeamID, body)
}

func (ra *ResourceAccess) CanUpdateSubDomainResource(domainTeamID, subDomainTeamID int, resourceUUID string, resourceUp map[string]interface{}) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessUpdate)
	url += fmt.Sprintf("&parent_team_id=%d&team_id=%d&resource_type=%s&resource_id=%s", domainTeamID, subDomainTeamID, common.SET_RESOURCE_TYPE_SUB_DOMAIN, resourceUUID)

	if err := PermitVerify(url, ra.UserInfo, subDomainTeamID); err != nil {
		return err
	}

	if resourceUp == nil || len(resourceUp) == 0 {
		return nil
	}

	var newTeamID int = subDomainTeamID
	teamID, tOK := resourceUp["team_id"]
	if tOK {
		newTeamID = int(teamID.(float64))
		url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessAdd)
		url += fmt.Sprintf("&parent_team_id=%d&team_id=%d", domainTeamID, newTeamID)
		if err := PermitVerify(url, ra.UserInfo, newTeamID); err != nil {
			return err
		}
	}
	return nil

	// TODO: support update
	// var newOwnerID int = ra.UserInfo.ID
	// userID, uOK := resourceUp["owner_user_id"]
	// if uOK {
	// 	newOwnerID = int(userID.(float64))
	// }
	// if tOK || uOK {
	// 	body := map[string]interface{}{
	// 		"new_team_id":   newTeamID,
	// 		"new_owner_id":  newOwnerID,
	// 		"resource_type": common.SET_RESOURCE_TYPE_SUB_DOMAIN,
	// 		"resource_id":   resourceUUID,
	// 	}
	// 	url = fmt.Sprintf(urlUGCPermission, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	// 	if err := ugcPermission(url, ra.UserInfo, body); err != nil {
	// 		return err
	// 	}
	// }

	// url = fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	// body := map[string]interface{}{
	// 	"resource_where": map[string]interface{}{
	// 		"resource_type": common.SET_RESOURCE_TYPE_SUB_DOMAIN,
	// 		"resource_id":   resourceUUID,
	// 	},
	// 	"resource_up": resourceUp,
	// }
	// return resourceVerify(url, http.MethodPatch, ra.UserInfo, domainTeamID, body)
}

func (ra *ResourceAccess) CanDeleteSubDomainResource(domainTeamID, subDomainTeamID int, resourceUUID string) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	url := fmt.Sprintf(urlPermitVerify, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, AccessDelete)
	url += fmt.Sprintf("&parent_team_id=%d&team_id=%d&resource_type=%s&resource_id=%s", domainTeamID, subDomainTeamID, common.SET_RESOURCE_TYPE_SUB_DOMAIN, resourceUUID)

	if err := PermitVerify(url, ra.UserInfo, subDomainTeamID); err != nil {
		return err
	}

	url = fmt.Sprintf(urlResource, ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID)
	body := map[string]interface{}{
		"resource_type": common.SET_RESOURCE_TYPE_SUB_DOMAIN,
		"resource_ids":  resourceUUID,
	}
	return resourceVerify(url, http.MethodDelete, ra.UserInfo, subDomainTeamID, body)
}

func (ra *ResourceAccess) CanOperateDomainResource(teamID int, domainUUID string) error {
	if !ra.Fpermit.Enabled {
		return nil
	}
	if (domainUUID == "" || domainUUID == common.DEFAULT_DOMAIN) &&
		ra.UserInfo.Type != common.USER_TYPE_SUPER_ADMIN {
		return fmt.Errorf("non-super administrators do not have permission to operate")
	}

	url := fmt.Sprintf("http://%s:%d/v1/org/%d/permit_verify?method=update&resource_type=domain&resource_id=%s",
		ra.Fpermit.Host, ra.Fpermit.Port, ra.UserInfo.ORGID, domainUUID)
	return PermitVerify(url, ra.UserInfo, teamID)
}

func PermitVerify(url string, userInfo *httpcommon.UserInfo, teamID int) error {
	resp, err := common.CURLPerform(
		http.MethodGet,
		url,
		make(map[string]interface{}),
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
	)
	if err != nil {
		log.Errorf("url(%s) user_type(%d) user_id(%d) error: %s", url, userInfo.Type, userInfo.ID, err.Error(), logger.NewORGPrefix(userInfo.ORGID))
		return response.ServiceError(httpcommon.FPERMIT_EXCEPTION, err.Error())
	}

	havePermission := resp.Get("DATA").MustBool()
	if !havePermission {
		desc := resp.Get("DESCRIPTION").MustString()
		log.Errorf("url(%s) user_type(%d) user_id(%d) team_id(%d) description(%s)",
			url, userInfo.Type, userInfo.ID, teamID, desc, logger.NewORGPrefix(userInfo.ORGID))
		return response.ServiceError(httpcommon.NO_PERMISSIONS, desc)
	}
	return nil
}

func ugcPermission(url string, userInfo *httpcommon.UserInfo, body map[string]interface{}) error {
	resp, err := common.CURLPerform(
		http.MethodPost,
		url,
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
		common.WithHeader(common.HEADER_KEY_X_APP_KEY, common.DEFAULT_APP_KEY),
	)
	if err != nil {
		log.Errorf("url(%s) user_type(%d) user_id(%d) body(%#v) error: %s",
			url, userInfo.Type, userInfo.ID, body, err.Error(), logger.NewORGPrefix(userInfo.ORGID))
		return response.ServiceError(httpcommon.FPERMIT_EXCEPTION, err.Error())
	}

	havePermission := resp.Get("DATA").MustBool()
	if !havePermission {
		desc := resp.Get("DESCRIPTION").MustString()
		log.Errorf("url(%s) user_type(%d) user_id(%d) body(%#v) description(%s)",
			url, userInfo.Type, userInfo.ID, body, desc, logger.NewORGPrefix(userInfo.ORGID))
		return response.ServiceError(httpcommon.NO_PERMISSIONS, desc)
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
		common.WithHeader(common.HEADER_KEY_X_APP_KEY, common.DEFAULT_APP_KEY),
	)
	if err != nil {
		log.Errorf("url(%s) user_type(%d) user_id(%d) team_id(%d) body(%#v) error: %s",
			url, userInfo.Type, userInfo.ID, teamID, body, err.Error(), logger.NewORGPrefix(userInfo.ORGID))
		return response.ServiceError(httpcommon.NO_PERMISSIONS, err.Error())
	}
	return nil
}
