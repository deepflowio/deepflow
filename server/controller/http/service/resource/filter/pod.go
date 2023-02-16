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

type PodFilterGenerator struct {
	FilterGeneratorBase
}

func NewPodFilterGenerator(fpermitCfg config.FPermit) *PodFilterGenerator {
	fg := new(PodFilterGenerator)
	fg.SetFPermit(fpermitCfg)
	fg.SetParentResourceTypes([]string{RESOURCE_TYPE_VPC, RESOURCE_TYPE_POD_NAMESPACE})
	fg.SetNonAdminUserExcludedFields([]string{"HOST_ID"})
	fg.SetConditionalFilterGenerator(fg)
	return fg
}

func (p *PodFilterGenerator) generateConditionalFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter {
	fcs := urlInfo.FilterConditions
	if ufcs := p.generateUserCondition(urlInfo, userInfo); ufcs != nil {
		for k, v := range ufcs {
			fcs[k] = v
		}
	}
	if len(fcs) == 0 {
		return nil
	}
	return NewPodConditionalFilter(FilterConditions{LOGICAL_AND: fcs})
}

func (p *PodFilterGenerator) generateUserCondition(urlInfo *model.URLInfo, userInfo *model.UserInfo) FilterConditions {
	userID := p.getNonAdminID(urlInfo, userInfo) // TODO common
	if userID == 0 {
		return nil
	}
	parentResources, _ := p.getUserPermittedResources(userID)
	fc := &model.PodFilterConditions{
		VPCIDs:          parentResources.VPCIDs,
		PodNamespaceIDs: parentResources.PodNamespaceIDs,
	}
	return p.combineUserConditions(fc.ToMapOmitEmpty())
}

type PodConditionalFilter struct {
	ConditionalFilter
	CombinedCondition
}

func NewPodConditionalFilter(cm FilterConditions) *PodConditionalFilter {
	f := new(PodConditionalFilter)
	f.Init(cm)
	f.TryAppendIntFieldCondition(NewPodServiceIDCondition("POD_SERVICE_ID", cm["POD_SERVICE_ID"].([]int)))
	f.TryAppendIntFieldCondition(NewSubnetIDCondition("SUBNET_ID", cm["SUBNET_ID"].([]int)))
	return f
}

type PodServiceIDCondition struct {
	FieldConditionBase[int]
}

func NewPodServiceIDCondition(key string, value []int) *PodServiceIDCondition {
	return &PodServiceIDCondition{FieldConditionBase[int]{key, value}}
}

func (p *PodServiceIDCondition) Keep(v ResponseElem) bool {
	podServices := v["POD_SERVICES"].([]map[string]interface{})
	for _, podService := range podServices {
		if common.Contains(p.value, podService["ID"].(int)) {
			return true
		}
	}
	return false
}

type SubnetIDCondition struct {
	FieldConditionBase[int]
}

func NewSubnetIDCondition(key string, value []int) *SubnetIDCondition {
	return &SubnetIDCondition{FieldConditionBase[int]{key, value}}
}

func (p *SubnetIDCondition) Keep(v ResponseElem) bool {
	subnets := v["SUBNETS"].([]map[string]interface{})
	for _, subnet := range subnets {
		if common.Contains(p.value, subnet["ID"].(int)) {
			return true
		}
	}
	return false
}
