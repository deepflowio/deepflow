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
	"golang.org/x/exp/slices"
)

type Network struct {
	FilterGeneratorComponent
}

func NewNetwork(fpermitCfg config.FPermit) *Network {
	g := new(Network)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetConditionConvertor(g)
	return g
}

func (p *Network) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.InitSkippedFields = []string{"ROUTER_ID"}
	c.Init(fcs)
	c.TryAppendIntFieldCondition(NewRouterIDCondition("ROUTER_ID", fcs["ROUTER_ID"].([]int)))
	return c
}

const (
	// TODO: move
	PUBLIC_NETWORK_ISP = 7
)

func (p *Network) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fc := &model.NetworkFilterConditions{
		VPCIDs: upr.VPCIDs,
	}
	fc.VPCIDs = append(fc.VPCIDs, GetRelatedVPCIDs(upr.PodNamespaceIDs)...)
	fc.ISP = []int{PUBLIC_NETWORK_ISP}
	return fc.ToMapOmitEmpty(), len(fc.VPCIDs) == 0
}

type RouterIDCondition struct {
	filter.FieldConditionBase[int]
}

func NewRouterIDCondition(key string, value []int) *RouterIDCondition {
	return &RouterIDCondition{filter.FieldConditionBase[int]{Key: key, Value: value}}
}

func (r *RouterIDCondition) Keep(v common.ResponseElem) bool {
	subnets := v["ROUTERS"].([]map[string]interface{})
	for _, item := range subnets {
		if slices.Contains(r.Value, item["ID"].(int)) {
			return true
		}
	}
	return false
}
