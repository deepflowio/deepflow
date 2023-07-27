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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type VInterface struct {
	FilterGeneratorComponent
}

func NewVInterface(fpermitCfg config.FPermit) *VInterface {
	g := new(VInterface)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetNonAdminUserExcludedFields(
		[]string{"HOST_ID", "HOST_NAME", "VTAP_NAME", "VTAP_LCUUID", "VTAP_ID", "VTAP_TYPE", "VTAP_GROUP_LCUUID", "VTAP_STATE"},
	)
	g.SetConditionConvertor(g)
	return g
}

func (v *VInterface) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.Init(fcs)
	return c
}

func (v *VInterface) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	vpcFC := &model.VInterfaceFilterConditions{
		VPCIDs: upr.VPCIDs,
	}
	vmFC := &model.VInterfaceFilterConditions{
		DeviceIDs:   GetRelatedVMIDs(upr.PodNamespaceIDs),
		DeviceTypes: []int{ctrlrcommon.VIF_DEVICE_TYPE_VM},
	}

	fc := vpcFC.ToMapOmitEmpty(vpcFC)
	if len(vmFC.DeviceIDs) > 0 {
		fc[filter.LOGICAL_AND] = vmFC.ToMapOmitEmpty(vmFC)
	}

	dropAll := (len(vpcFC.VPCIDs) == 0 && len(vmFC.DeviceIDs) == 0)
	return common.FilterConditions{filter.LOGICAL_OR: fc}, dropAll
}
