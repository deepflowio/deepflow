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

package volcengine

import (
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getVMs(sess *session.Session) ([]model.VM, []model.VInterface, []model.IP, error) {
	log.Debug("get vms starting", logger.NewORGPrefix(v.orgID))
	var vms []model.VM
	var vinterfaces []model.VInterface
	var ips []model.IP

	var retVMs []*ecs.InstanceForDescribeInstancesOutput
	var nextToken *string
	var maxResults int32 = 100
	for {
		input := &ecs.DescribeInstancesInput{MaxResults: &maxResults, NextToken: nextToken}
		result, err := ecs.New(sess).DescribeInstances(input)
		if err != nil {
			log.Errorf("request volcengine (ecs.DescribeInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.VM{}, []model.VInterface{}, []model.IP{}, err
		}
		retVMs = append(retVMs, result.Instances...)
		if v.getStringPointerValue(result.NextToken) == "" {
			break
		}
		nextToken = result.NextToken
	}

	for _, retVM := range retVMs {
		if retVM == nil {
			continue
		}
		azLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(retVM.ZoneId))
		instanceID := v.getStringPointerValue(retVM.InstanceId)
		vmName := v.getStringPointerValue(retVM.InstanceName)
		vmLcuuid := common.GetUUIDByOrgID(v.orgID, instanceID)
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(retVM.VpcId))
		vmState, ok := vmStates[v.getStringPointerValue(retVM.Status)]
		if !ok {
			vmState = common.VM_STATE_EXCEPTION
		}
		createStr := v.getStringPointerValue(retVM.CreatedAt)
		createAt, err := time.ParseInLocation(time.RFC3339, createStr, time.Local)
		if err != nil {
			log.Infof("parse vm (%s) create at (%s) failed", vmName, createStr, logger.NewORGPrefix(v.orgID))
		}
		tags := map[string]string{}
		for _, tag := range retVM.Tags {
			if tag == nil {
				continue
			}
			tags[v.getStringPointerValue(tag.Key)] = v.getStringPointerValue(tag.Value)
		}
		vm := model.VM{
			Lcuuid:       vmLcuuid,
			Name:         vmName,
			Label:        instanceID,
			Hostname:     v.getStringPointerValue(retVM.Hostname),
			CloudTags:    tags,
			State:        vmState,
			HType:        common.VM_HTYPE_VM_C,
			CreatedAt:    createAt,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: v.regionLcuuid,
		}
		v.azLcuuids[azLcuuid] = false

		var vmPrimaryIP string
		for _, net := range retVM.NetworkInterfaces {
			if net == nil {
				continue
			}
			mac := v.getStringPointerValue(net.MacAddress)
			vinterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(net.NetworkInterfaceId))
			networkLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(net.SubnetId))
			vinterfaces = append(vinterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           mac,
				DeviceLcuuid:  vmLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				VPCLcuuid:     vpcLcuuid,
				NetworkLcuuid: networkLcuuid,
				RegionLcuuid:  v.regionLcuuid,
			})

			privateIP := v.getStringPointerValue(net.PrimaryIpAddress)
			if v.getStringPointerValue(net.Type) == "primary" {
				vmPrimaryIP = privateIP
			}
			ips = append(ips, model.IP{
				Lcuuid:           common.GetUUIDByOrgID(v.orgID, vinterfaceLcuuid+privateIP),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               privateIP,
				SubnetLcuuid:     common.GetUUIDByOrgID(v.orgID, networkLcuuid),
				RegionLcuuid:     v.regionLcuuid,
			})
		}
		vm.IP = vmPrimaryIP
		vms = append(vms, vm)

		if retVM.EipAddress == nil {
			continue
		}
		eID := v.getStringPointerValue(retVM.EipAddress.AllocationId)
		eIP := v.getStringPointerValue(retVM.EipAddress.IpAddress)
		eVInterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, eID+eIP)
		vinterfaces = append(vinterfaces, model.VInterface{
			Lcuuid:        eVInterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  vmLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_VM,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: common.NETWORK_ISP_LCUUID,
			RegionLcuuid:  v.regionLcuuid,
		})
		ips = append(ips, model.IP{
			Lcuuid:           common.GetUUIDByOrgID(v.orgID, eID),
			IP:               eIP,
			VInterfaceLcuuid: eVInterfaceLcuuid,
			SubnetLcuuid:     common.SUBNET_ISP_LCUUID,
			RegionLcuuid:     v.regionLcuuid,
		})
	}
	log.Debug("get vms complete", logger.NewORGPrefix(v.orgID))
	return vms, vinterfaces, ips, nil
}
