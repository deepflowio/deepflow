/**
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

package generator

import (
	"fmt"
	"strings"

	"github.com/op/go-logging"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

var log = logging.MustGetLogger("http.service.resource.filter.generator")

type FilterGenerator interface {
	Generate(*model.URLInfo, *model.UserInfo) (f []filter.Filter, dropAll bool)
}

type FilterGeneratorComponent struct {
	fieldFilterGeneratorComponent
	conditionFilterGeneratorComponent
}

func (f *FilterGeneratorComponent) SetNonAdminUserExcludedFields(fields []string) {
	f.fieldFilterGeneratorComponent.nonAdminReqUserExcludedFields = fields
}

func (f *FilterGeneratorComponent) SetConditionConvertor(cc conditionConvertor) {
	f.conditionFilterGeneratorComponent.conditionConv = cc
	f.userFilterConditionsGeneratorComponent.conditionConv = cc
}

func (f *FilterGeneratorComponent) SetFPermit(cfg config.FPermit) {
	f.userFilterConditionsGeneratorComponent.fpermitCfg = cfg
}

func (f *FilterGeneratorComponent) SetParentResourceTypes(types []string) {
	f.userFilterConditionsGeneratorComponent.parentResourceTypes = types
}

func (f *FilterGeneratorComponent) SetNonAdminDropAll() {
	f.userFilterConditionsGeneratorComponent.nonAdminDropAll = true
}

func (f *FilterGeneratorComponent) Generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) (fs []filter.Filter, dropAll bool) {
	if f, dropAll := f.conditionFilterGeneratorComponent.generate(urlInfo, userInfo); dropAll {
		return fs, true
	} else if f != nil {
		fs = append(fs, f)
	}
	if f := f.fieldFilterGeneratorComponent.generate(urlInfo, userInfo); f != nil {
		fs = append(fs, f)
	}
	return fs, false
}

type fieldFilterGeneratorComponent struct {
	nonAdminReqUserExcludedFields []string
}

func (f *fieldFilterGeneratorComponent) generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) filter.Filter {
	ff := new(filter.FieldFilter)
	if len(urlInfo.IncludedFields) != 0 {
		ff.IncludedFields = urlInfo.IncludedFields
	}
	// excludes fields only when request user identified by header info is non admin
	// 仅当请求用户（使用 header 中的用户信息判断）本身为非管理用户时，隐藏一部分返回字段
	if len(f.nonAdminReqUserExcludedFields) != 0 && !IsAdmin(userInfo.Type) {
		ff.ExcludedFields = append(ff.ExcludedFields, f.nonAdminReqUserExcludedFields...)
	}
	if len(ff.IncludedFields) == 0 && len(ff.IncludedFields) == 0 {
		return nil
	}
	return ff
}

type conditionConvertor interface {
	conditionsMapToStruct(common.FilterConditions) filter.Condition
	userPermittedResourceToConditions(*UserPermittedResource) (common.FilterConditions, bool)
}

type conditionFilterGeneratorComponent struct {
	userFilterConditionsGeneratorComponent
	conditionConv conditionConvertor
}

func (c *conditionFilterGeneratorComponent) generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) (f filter.Filter, dropAll bool) {
	userFCs, dropAll := c.userFilterConditionsGeneratorComponent.generate(urlInfo, userInfo)
	if dropAll {
		return nil, true
	}
	fcs := c.combineFilterConditions(urlInfo.FilterConditions, userFCs)
	if len(fcs) == 0 {
		return nil, false
	}
	return filter.NewConditionFilter(c.conditionConv.conditionsMapToStruct(fcs)), false
}

// combineFilterConditions combines filter conditions in url query and filter conditions extracted from user id
func (c *conditionFilterGeneratorComponent) combineFilterConditions(urlFCs common.FilterConditions, userFCs common.FilterConditions) common.FilterConditions {
	fcs := make(common.FilterConditions)
	if len(userFCs) != 0 {
		urlFCs[filter.LOGICAL_OR] = userFCs
	}
	if len(urlFCs) != 0 {
		fcs[filter.LOGICAL_AND] = urlFCs
	}
	return fcs
}

type userFilterConditionsGeneratorComponent struct {
	nonAdminDropAll     bool
	fpermitCfg          config.FPermit
	parentResourceTypes []string
	conditionConv       conditionConvertor
}

func (u *userFilterConditionsGeneratorComponent) generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) (fc common.FilterConditions, dropAll bool) {
	// Generates user filter conditions only when fpermit service is supported
	// 仅当支持租户授权模块时，需要生成租户过滤条件
	if !u.fpermitCfg.Enabled { // TODO use userinfo check ?
		return nil, false
	}
	if u.nonAdminDropAll {
		return nil, true
	}
	parentResources, dropAll := u.getUserPermittedParentResources(urlInfo, userInfo)
	if dropAll {
		return nil, true
	}
	if parentResources == nil || !parentResources.HasPermittedResource() {
		return nil, false
	}
	return u.conditionConv.userPermittedResourceToConditions(parentResources)
}

func (u *userFilterConditionsGeneratorComponent) getUserPermittedParentResources(urlInfo *model.URLInfo, userInfo *model.UserInfo) (upr *UserPermittedResource, dropAll bool) {
	userID := u.extractNonAdminID(urlInfo, userInfo)
	if userID == 0 {
		return nil, false
	}
	parentResources, err := u.getUserPermittedResource(userID)
	if err != nil {
		return nil, true
	}
	return parentResources, false
}

func (u *userFilterConditionsGeneratorComponent) extractNonAdminID(urlInfo *model.URLInfo, userInfo *model.UserInfo) int {
	if IsAdmin(userInfo.Type) {
		return urlInfo.UserID
	} else {
		return userInfo.ID
	}
}

func (u *userFilterConditionsGeneratorComponent) getUserPermittedResource(userID int) (*UserPermittedResource, error) {
	body := make(map[string]interface{})
	response, err := ctrlrcommon.CURLPerform(
		"GET",
		fmt.Sprintf(
			"http://%s:%d/permission-user?permission_detail=1&my_self=1&user_id=%d&&resource_type=%s",
			u.fpermitCfg.Host, u.fpermitCfg.Port, userID, strings.Join(u.parentResourceTypes, ","),
		),
		body,
	)
	if err != nil {
		return nil, err
	}
	var upr *UserPermittedResource
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		if data.Get("RESOURCE_TYPE").MustString() == FPERMIT_RESOURCE_TYPE_VPC {
			upr.VPCIDs = append(upr.VPCIDs, data.Get("RESOURCE_ID").MustInt())
		}
		if data.Get("RESOURCE_TYPE").MustString() == FPERMIT_RESOURCE_TYPE_POD_NAMESPACE {
			upr.PodNamespaceIDs = append(upr.PodNamespaceIDs, data.Get("RESOURCE_ID").MustInt())
		}
	}
	return upr, nil
}
