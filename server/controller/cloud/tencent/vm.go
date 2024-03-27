/*
 * Copyright (c) 2024 Yunshan Networks
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

package tencent

import (
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/tencent/expand"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getVMs(region tencentRegion) ([]model.VM, []model.VMSecurityGroup, error) {
	log.Debug("get vms starting")
	var vms []model.VM
	var vmSGs []model.VMSecurityGroup
	states := map[string]int{
		"RUNNING": common.VM_STATE_RUNNING,
		"STOPPED": common.VM_STATE_STOPPED,
	}

	attrs := []string{"InstanceId", "InstanceName", "InstanceState", "SecurityGroupIds", "VirtualPrivateCloud", "CreatedTime"}
	resp, err := t.getResponse("cvm", "2017-03-12", "DescribeInstances", region.name, "InstanceSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("vm request tencent api error: (%s)", err.Error())
		return []model.VM{}, []model.VMSecurityGroup{}, err
	}
	for _, vData := range resp {
		if !t.checkRequiredAttributes(vData, attrs) {
			continue
		}
		vmName := vData.Get("InstanceName").MustString()
		vpcID := vData.Get("VirtualPrivateCloud").Get("VpcId").MustString()
		if vpcID == "" {
			log.Infof("vm (%s) vpc not found", vmName)
			continue
		}

		vmID := vData.Get("InstanceId").MustString()
		vmLcuuid := common.GenerateUUID(vmID)

		vmState := vData.Get("InstanceState").MustString()
		state, ok := states[vmState]
		if !ok {
			state = common.VM_STATE_EXCEPTION
		}

		vmCteateAt := vData.Get("CreatedTime").MustString()
		createAt, err := time.ParseInLocation(time.RFC3339, vmCteateAt, time.Local)
		if err != nil {
			log.Warningf("vm (%s) created time format error: %s", vmName, err.Error())
		}

		azID := vData.Get("Placement").Get("Zone").MustString()
		azLcuuid := common.GenerateUUID(t.uuidGenerate + "_" + azID)
		vms = append(vms, model.VM{
			Lcuuid:       vmLcuuid,
			Name:         vmName,
			Label:        vmID,
			HType:        common.VM_HTYPE_VM_C,
			State:        state,
			CreatedAt:    createAt,
			CloudTags:    expand.GetVMTags(vData),
			VPCLcuuid:    common.GenerateUUID(vpcID),
			AZLcuuid:     azLcuuid,
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})
		t.azLcuuidMap[azLcuuid] = 0

		sgIDs := vData.Get("SecurityGroupIds")
		for s := range sgIDs.MustArray() {
			sgID := sgIDs.GetIndex(s).MustString()
			vmSGs = append(vmSGs, model.VMSecurityGroup{
				Lcuuid:              common.GenerateUUID(vmLcuuid + sgID),
				SecurityGroupLcuuid: common.GenerateUUID(sgID),
				VMLcuuid:            vmLcuuid,
				Priority:            s,
			})
		}
	}
	log.Debug("get vms complete")
	return vms, vmSGs, nil
}
