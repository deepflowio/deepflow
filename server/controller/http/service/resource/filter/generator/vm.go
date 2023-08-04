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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type VM struct {
	FilterGeneratorComponent
}

func NewVM(fpermitCfg config.FPermit) *VM {
	g := new(VM)
	g.SetFPermit(fpermitCfg)
	g.SetParentResourceTypes([]string{FPERMIT_RESOURCE_TYPE_VPC, FPERMIT_RESOURCE_TYPE_POD_NAMESPACE})
	g.SetNonAdminUserExcludedFields(
		[]string{"HOST_ID", "HOST_NAME", "VTAP_NAME", "VTAP_LCUUID", "VTAP_ID", "VTAP_TYPE", "VTAP_GROUP_LCUUID", "VTAP_STATE"},
	)
	g.SetConditionConvertor(g)
	return g
}

func (v *VM) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	log.Info(fcs) // TODO delete
	c := filter.NewAND()
	c.InitSkippedFields = []string{"SUBNET_ID", "SECURITY_GROUP_ID"}
	c.Init(fcs)
	if sgIDs, ok := fcs["SECURITY_GROUP_ID"]; ok {
		c.TryAppendIntFieldCondition(NewSecurityGroupIDCondition("SECURITY_GROUP_ID", sgIDs))
	}
	if networkIDs, ok := fcs["SUBNET_ID"]; ok {
		c.TryAppendIntFieldCondition(NewSubnetIDCondition("SUBNET_ID", networkIDs))
	}
	log.Infof("%#v", c) // TODO delete
	return c
}

func (v *VM) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	fc := &model.VMFilterConditions{
		VPCIDs: upr.VPCIDs,
	}
	fc.IDs = append(fc.IDs, GetRelatedVMIDs(upr.PodNamespaceIDs)...)
	dropAll := (len(fc.VPCIDs) == 0 && len(fc.IDs) == 0)
	return fc.ToMapOmitEmpty(fc), dropAll
}

// TODO use singleflight
func GetRelatedVMIDs(podNamespaceIDs []int) []int {
	var vmIDs []int
	var pods []mysql.Pod
	err := mysql.Db.Where("pod_namespace_id in ?", podNamespaceIDs).Find(&pods).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}
	var podNodeIDs []int
	for _, pod := range pods {
		podNodeIDs = append(podNodeIDs, pod.PodNodeID)
	}
	var vmPodNodeConns []mysql.VMPodNodeConnection
	err = mysql.Db.Where("pod_node_id in ?", podNodeIDs).Find(&vmPodNodeConns).Error
	if err != nil {
		log.Errorf("db query failed; %s", err.Error())
	}
	for _, conn := range vmPodNodeConns {
		vmIDs = append(vmIDs, conn.VMID)
	}
	return vmIDs
}

type SubnetIDCondition struct {
	filter.FieldConditionBase[float64]
}

func NewSubnetIDCondition(key string, value interface{}) *SubnetIDCondition {
	return &SubnetIDCondition{filter.FieldConditionBase[float64]{Key: key, Value: filter.ConvertValueToSlice[float64](value)}}
}

func (p *SubnetIDCondition) Keep(v common.ResponseElem) bool {
	subnets := v["SUBNETS"].([]map[string]interface{})
	for _, item := range subnets {
		if slices.Contains(p.Value, float64(item["ID"].(int))) {
			return true
		}
	}
	return false
}

type SecurityGroupIDCondition struct {
	filter.FieldConditionBase[float64]
}

func NewSecurityGroupIDCondition(key string, value interface{}) *SecurityGroupIDCondition {
	return &SecurityGroupIDCondition{filter.FieldConditionBase[float64]{Key: key, Value: filter.ConvertValueToSlice[float64](value)}}
}

func (p *SecurityGroupIDCondition) Keep(v common.ResponseElem) bool {
	sgs := v["SECURITY_GROUPS"].([]map[string]interface{})
	for _, item := range sgs {
		if slices.Contains(p.Value, float64(item["ID"].(int))) {
			return true
		}
	}
	return false
}
