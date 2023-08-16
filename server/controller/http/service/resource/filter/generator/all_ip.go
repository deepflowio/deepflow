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
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type AllIP struct {
	FilterGeneratorComponent
}

func NewAllIP(fpermitCfg config.FPermit) *AllIP {
	g := new(AllIP)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetConditionConvertor(g)
	return g
}

func (p *AllIP) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.InitSkippedFields = []string{"IP_VERSION"}
	c.Init(fcs)
	c.TryAppendIntFieldCondition(NewIPVersionCondition("IP_VERSION", fcs["IP_VERSION"].([]float64)))
	return c
}

func (p *AllIP) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fc1 := &model.IPFilterConditions{
		VPCIDs: upr.VPCIDs,
	}
	vmIDs := GetRelatedDeviceVMIDs(upr.PodNamespaceIDs)
	fc2 := &model.IPFilterConditions{
		DeviceType: []int{ctrlcommon.VIF_DEVICE_TYPE_VM},
		DeviceIDs:  vmIDs,
	}
	dropAll := (len(fc1.VPCIDs) == 0 && len(vmIDs) == 0)

	data := make(common.FilterConditions)
	data[filter.LOGICAL_OR] = common.FilterConditions{
		filter.LOGICAL_OR:  fc1.ToMapOmitEmpty(fc1),
		filter.LOGICAL_AND: fc2.ToMapOmitEmpty(fc2),
	}
	return data, dropAll
}
