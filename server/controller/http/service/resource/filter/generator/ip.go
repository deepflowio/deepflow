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
	"strings"

	"golang.org/x/exp/slices"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type IP struct {
	FilterGeneratorComponent
}

func NewIP(fpermitCfg config.FPermit) *IP {
	g := new(IP)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetConditionConvertor(g)
	return g
}

func (p *IP) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.InitSkippedFields = []string{"IP_VERSION"}
	c.Init(fcs)
	c.TryAppendIntFieldCondition(NewIPVersionCondition("IP_VERSION", fcs["IP_VERSION"].([]int)))
	return c
}

func (p *IP) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
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
		filter.LOGICAL_OR:  fc1.ToMapOmitEmpty(),
		filter.LOGICAL_AND: fc2.ToMapOmitEmpty(),
	}
	return data, dropAll
}

// TODO use singleflight
func GetRelatedDeviceVMIDs(podNamespaceIDs []int) []int {
	vmIDs := GetRelatedVMIDs(podNamespaceIDs)
	var vms []mysql.VM
	err := mysql.Db.Where("id in ?", vmIDs).Find(&vms).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}

	var vInterfaces []mysql.VInterface
	err = mysql.Db.Where("devicetype = ? and deviceid in ?", ctrlcommon.VIF_DEVICE_TYPE_VM, vmIDs).Find(&vInterfaces).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}
	var ids []int
	for _, vinterface := range vInterfaces {
		ids = append(ids, vinterface.DeviceID)
	}
	return ids
}

type IPVersionCondition struct {
	filter.FieldConditionBase[int]
}

func NewIPVersionCondition(key string, value []int) *IPVersionCondition {
	return &IPVersionCondition{filter.FieldConditionBase[int]{Key: key, Value: value}}
}

const (
	// TODO: move to common
	IP_VERSION_IPV4 = 4
	IP_VERSION_IPV6 = 6
)

func (i *IPVersionCondition) Keep(v common.ResponseElem) bool {
	ip := v["IP"].(string)
	if slices.Contains(i.Value, IP_VERSION_IPV4) && strings.Contains(ip, ":") {
		return false
	}
	if slices.Contains(i.Value, IP_VERSION_IPV6) && !strings.Contains(ip, ":") {
		return false
	}
	return true
}
