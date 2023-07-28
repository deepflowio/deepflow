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

type VPC struct {
	FilterGeneratorComponent
}

func NewVPC(fpermitCfg config.FPermit) *VPC {
	g := new(VPC)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetConditionConvertor(g)
	return g
}

func (p *VPC) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.Init(fcs)
	return c
}

func (p *VPC) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fc := &model.VPCFilterConditions{
		IDs: upr.VPCIDs,
	}
	fc.IDs = append(fc.IDs, GetRelatedVPCIDs(upr.PodNamespaceIDs)...)
	return fc.ToMapOmitEmpty(fc), len(fc.IDs) == 0
}

// TODO use singleflight
func GetRelatedVPCIDs(podNamespaceIDs []int) []int {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Where("id in ?", podNamespaceIDs).Find(&podNamespaces).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}
	var clusterIDs []int
	for _, podNamespace := range podNamespaces {
		clusterIDs = append(clusterIDs, podNamespace.PodClusterID)
	}
	var podClusters []mysql.PodCluster
	err = mysql.Db.Where("id in ?", clusterIDs).Find(&podClusters).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}

	var ids []int
	for _, podCluster := range podClusters {
		ids = append(ids, podCluster.VPCID)
	}
	return ids
}
