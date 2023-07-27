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
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type Pod struct {
	FilterGeneratorComponent
}

func NewPod(fpermitCfg config.FPermit) *Pod {
	g := new(Pod)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetNonAdminUserExcludedFields([]string{"HOST_ID"})
	g.SetConditionConvertor(g)
	return g
}

func (p *Pod) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.InitSkippedFields = []string{"POD_SERVICE_ID", "SUBNET_ID"}
	c.Init(fcs)
	c.TryAppendIntFieldCondition(NewPodServiceIDCondition("POD_SERVICE_ID", fcs["POD_SERVICE_ID"].([]int)))
	c.TryAppendIntFieldCondition(NewSubnetIDCondition("SUBNET_ID", fcs["SUBNET_ID"].([]int)))
	return c
}

func (p *Pod) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fcs := &model.PodFilterConditions{
		VPCIDs:          upr.VPCIDs,
		PodNamespaceIDs: upr.PodNamespaceIDs,
	}
	dropAll := (len(fcs.VPCIDs) == 0 && len(fcs.PodNamespaceIDs) == 0)
	return fcs.ToMapOmitEmpty(), dropAll
}

type PodServiceIDCondition struct {
	filter.FieldConditionBase[int]
}

func NewPodServiceIDCondition(key string, value []int) *PodServiceIDCondition {
	return &PodServiceIDCondition{filter.FieldConditionBase[int]{Key: key, Value: value}}
}

func (p *PodServiceIDCondition) Keep(v common.ResponseElem) bool {
	podServices := v["POD_SERVICES"].([]map[string]interface{})
	for _, item := range podServices {
		if slices.Contains(p.Value, item["ID"].(int)) {
			return true
		}
	}
	return false
}
