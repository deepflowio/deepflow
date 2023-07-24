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
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type PodNamespace struct {
	FilterGeneratorComponent
}

func NewPodNamespace(fpermitCfg config.FPermit) *PodNamespace {
	g := new(PodNamespace)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetConditionConvertor(g)
	return g
}

func (p *PodNamespace) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.Init(fcs)
	return c
}

func (p *PodNamespace) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fcs := &model.PodNamespaceFilterConditions{
		VPCIDs: upr.VPCIDs,
		IDs:    upr.PodNamespaceIDs,
	}
	dropAll := (len(fcs.VPCIDs) == 0 && len(fcs.IDs) == 0)
	return fcs.ToMapOmitEmpty(), dropAll
}
