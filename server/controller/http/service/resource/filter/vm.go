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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type VMFilterGenerator struct {
	FilterGeneratorBase
}

func NewVMFilterGenerator(fpermitCfg config.FPermit) *VMFilterGenerator {
	fg := new(VMFilterGenerator)
	fg.SetFPermit(fpermitCfg)
	fg.SetParentResourceTypes([]string{RESOURCE_TYPE_VPC, RESOURCE_TYPE_POD_NAMESPACE})
	fg.SetNonAdminUserExcludedFields(
		[]string{"HOST_ID", "HOST_NAME", "VTAP_NAME", "VTAP_LCUUID", "VTAP_ID", "VTAP_TYPE", "VTAP_GROUP_LCUUID", "VTAP_STATE"},
	)
	fg.SetConditionalFilterGenerator(fg)
	return fg
}

func (p *VMFilterGenerator) generateConditionalFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter {
	fcs := urlInfo.FilterConditions
	if ufcs := p.generateUserCondition(urlInfo, userInfo); ufcs != nil {
		for k, v := range ufcs {
			fcs[k] = v
		}
	}
	if len(fcs) == 0 {
		return nil
	}
	return NewVMConditionalFilter(FilterConditions{LOGICAL_AND: fcs})
}

func (p *VMFilterGenerator) generateUserCondition(urlInfo *model.URLInfo, userInfo *model.UserInfo) FilterConditions {
	userID := p.getNonAdminID(urlInfo, userInfo)
	if userID == 0 {
		return nil
	}
	parentResources, _ := p.getUserPermittedResources(userID)
	fc := &model.VMFilterConditions{
		VPCIDs: parentResources.VPCIDs,
	}
	return p.combineUserConditions(fc.ToMapOmitEmpty())
}

type VMConditionalFilter struct {
	ConditionalFilter
	CombinedCondition
}

func NewVMConditionalFilter(cm FilterConditions) *VMConditionalFilter {
	f := new(VMConditionalFilter)
	f.Init(cm)
	f.TryAppendIntFieldCondition(NewSubnetIDCondition("SUBNET_ID", cm["SUBNET_ID"].([]int)))
	f.TryAppendIntFieldCondition(NewSecurityGroupIDCondition("SECURITY_GROUP_ID", cm["SECURITY_GROUP_ID"].([]int)))
	return f
}

type SecurityGroupIDCondition struct {
	FieldConditionBase[int]
}

func NewSecurityGroupIDCondition(key string, value []int) *SecurityGroupIDCondition {
	return &SecurityGroupIDCondition{FieldConditionBase[int]{key, value}}
}

func (p *SecurityGroupIDCondition) Keep(v ResponseElem) bool {
	sgs := v["SECURITY_GROUPS"].([]map[string]interface{})
	for _, sg := range sgs {
		if common.Contains(p.value, sg["ID"].(int)) {
			return true
		}
	}
	return false
}
