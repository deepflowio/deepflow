/*
 * Copyright (c) 2023 Yunshan Networks
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

package filter

import (
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type FilterGenerator interface {
	Generate(*model.URLInfo, *model.UserInfo) []Filter
}

type FilterGeneratorBase struct {
	fpermitCfg                 config.FPermit
	parentResourceTypes        []string
	nonAdminUserExcludedFields []string
	conditionalFilterGenerator ConditionalFilterGenerator
}

func (fgb *FilterGeneratorBase) SetFPermit(cfg config.FPermit) {
	fgb.fpermitCfg = cfg
}

func (fgb *FilterGeneratorBase) SetParentResourceTypes(types []string) {
	fgb.parentResourceTypes = types
}

func (fgb *FilterGeneratorBase) SetNonAdminUserExcludedFields(fields []string) {
	fgb.nonAdminUserExcludedFields = fields
}

func (fgb *FilterGeneratorBase) SetConditionalFilterGenerator(cfg ConditionalFilterGenerator) {
	fgb.conditionalFilterGenerator = cfg
}

func (fgb *FilterGeneratorBase) Generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) []Filter {
	var fs []Filter
	if f := fgb.conditionalFilterGenerator.generateConditionalFilter(urlInfo, userInfo); f != nil {
		fs = append(fs, f)
	} else {
		return nil
	}
	if f := fgb.generatePartialFilter(urlInfo, userInfo); f != nil { // TODO use next?
		fs = append(fs, f)
	}
	return fs
}

func (fgb *FilterGeneratorBase) generatePartialFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter {
	f := new(PartialFilter)
	if len(urlInfo.IncludedFields) != 0 {
		f.includedFields = urlInfo.IncludedFields
	}
	if !IsAdmin(userInfo.Type) {
		f.excludedFields = append(f.excludedFields, fgb.nonAdminUserExcludedFields...)
	}
	if len(f.excludedFields) == 0 && len(f.includedFields) == 0 {
		return nil
	}
	return f
}

func (fgb *FilterGeneratorBase) getNonAdminID(urlInfo *model.URLInfo, userInfo *model.UserInfo) int {
	var userID int
	if IsAdmin(userInfo.Type) {
		if urlInfo.UserID != 0 {
			userID = urlInfo.UserID
		} else {
			return 0
		}
	} else {
		userID = userInfo.ID
	}
	return userID
}

func (fgb *FilterGeneratorBase) combineUserConditions(fcs FilterConditions) FilterConditions {
	result := make(FilterConditions)
	result[LOGICAL_OR] = fcs
	return result
}

func (fgb *FilterGeneratorBase) getUserPermittedResources(userID int) (*UserResource, error) {
	body := make(map[string]interface{})
	response, err := common.CURLPerform(
		"GET",
		fmt.Sprintf(
			"http://%s:%d/permission-user?permission_detail=1&my_self=1&user_id=%d&&resource_type=%s",
			fgb.fpermitCfg.Host, fgb.fpermitCfg.Port, userID, strings.Join(fgb.parentResourceTypes, ","),
		),
		body,
	)
	if err != nil {
		return nil, err
	}
	var userResource *UserResource
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		if data.Get("RESOURCE_TYPE").MustString() == RESOURCE_TYPE_VPC {
			userResource.VPCIDs = append(userResource.VPCIDs, data.Get("RESOURCE_ID").MustInt())
		}
		if data.Get("RESOURCE_TYPE").MustString() == RESOURCE_TYPE_POD_NAMESPACE {
			userResource.PodNamespaceIDs = append(userResource.PodNamespaceIDs, data.Get("RESOURCE_ID").MustInt())
		}
	}
	return userResource, nil
}

var RESOURCE_TYPE_VPC = "vpc"
var RESOURCE_TYPE_POD_NAMESPACE = "namespace"

type UserResource struct { // TODO name
	VPCIDs          []int
	PodNamespaceIDs []int
}

type ConditionalFilterGenerator interface {
	generateConditionalFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter
}

func IsAdmin(userType int) bool {
	if common.Contains([]int{USER_TYPE_SUPER_ADMIN, USER_TYPE_ADMIN}, userType) {
		return true
	}
	return false
}
