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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type PodNode struct {
	FilterGeneratorComponent
}

func NewPodNode(fpermitCfg config.FPermit) *PodNode {
	g := new(PodNode)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetNonAdminUserExcludedFields([]string{"VTAP_NAME", "VTAP_LCUUID", "VTAP_TYPE", "VTAP_ID",
		"VTAP_GROUP_LCUUID", "VTAP_STATE"})
	g.SetConditionConvertor(g)
	return g
}

func (p *PodNode) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.Init(fcs)
	return c
}

func (p *PodNode) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fc := &model.PodNodeFilterConditions{
		VPCIDs:        upr.VPCIDs,
		PodClusterIDs: GetRelatedPodClusterIDs(upr.PodNamespaceIDs),
	}
	dropAll := (len(fc.VPCIDs) == 0 && len(fc.PodClusterIDs) == 0)
	return fc.ToMapOmitEmpty(fc), dropAll
}

// TODO use singleflight
func GetRelatedPodClusterIDs(podNamespaceIDs []int) []int {
	var podNSs []mysql.PodNamespace
	err := mysql.Db.Where("id in ?", podNamespaceIDs).Find(&podNSs).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}

	var podClusterIDs []int
	for _, podNS := range podNSs {
		podClusterIDs = append(podClusterIDs, podNS.PodClusterID)
	}
	return podClusterIDs
}
