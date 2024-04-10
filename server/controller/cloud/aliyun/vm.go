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

package aliyun

import (
	"strings"
	"time"

	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getVMs(region model.Region) (
	[]model.VM, []model.VMSecurityGroup, []model.VInterface, []model.IP, []model.FloatingIP, map[string]string, error,
) {
	var retVMs []model.VM
	var retVMSecurityGroups []model.VMSecurityGroup
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP
	var vmLcuuidToVPCLcuuid = make(map[string]string)

	log.Debug("get vms starting")
	request := ecs.CreateDescribeInstancesRequest()
	response, err := a.getVMResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retVMs, retVMSecurityGroups, retVInterfaces, retIPs, retFloatingIPs, vmLcuuidToVPCLcuuid, err
	}

	for _, r := range response {
		vms, _ := r.Get("Instance").Array()
		for i := range vms {
			vm := r.Get("Instance").GetIndex(i)

			err := a.checkRequiredAttributes(
				vm,
				[]string{
					"InstanceId", "InstanceName", "Status", "CreationTime", "ZoneId", "VpcAttributes",
				},
			)
			if err != nil {
				continue
			}

			vmId := vm.Get("InstanceId").MustString()
			vmName := vm.Get("InstanceName").MustString()
			if vmName == "" {
				vmName = vmId
			}
			vmStatus := vm.Get("Status").MustString()
			zoneId := vm.Get("ZoneId").MustString()
			createdTime := vm.Get("CreationTime").MustString()
			vpcId := vm.Get("VpcAttributes").Get("VpcId").MustString()
			if vpcId == "" {
				log.Infof("no vpcId in vm (%s) data", vmId)
				continue
			}

			vmLcuuid := common.GenerateUUIDByOrgID(a.orgID, vmId)
			VPCLcuuid := common.GenerateUUIDByOrgID(a.orgID, vpcId)
			vmState := common.VM_STATE_EXCEPTION
			if vmStatus == "Running" {
				vmState = common.VM_STATE_RUNNING
			} else if vmStatus == "Stopped" {
				vmState = common.VM_STATE_STOPPED
			}
			createdAt, _ := time.Parse(common.GO_BIRTHDAY, createdTime)
			vmLcuuidToVPCLcuuid[vmLcuuid] = VPCLcuuid

			var pIP string
			networks := vm.GetPath("NetworkInterfaces", "NetworkInterface")
			for n := range networks.MustArray() {
				network := networks.GetIndex(n)
				if network.Get("Type").MustString() == "Primary" {
					pIP = network.Get("PrimaryIpAddress").MustString()
					break
				}
			}

			retVM := model.VM{
				Lcuuid:       vmLcuuid,
				Name:         vmName,
				Label:        vmId,
				HType:        common.VM_HTYPE_VM_C,
				VPCLcuuid:    VPCLcuuid,
				State:        vmState,
				IP:           pIP,
				CreatedAt:    createdAt,
				AZLcuuid:     common.GenerateUUIDByOrgID(a.orgID, a.uuidGenerate+"_"+zoneId),
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retVMs = append(retVMs, retVM)
			a.azLcuuidToResourceNum[retVM.AZLcuuid]++
			a.regionLcuuidToResourceNum[retVM.RegionLcuuid]++

			// VM与安全组关联关系
			securityGroupIds := vm.Get("SecurityGroupIds").Get("SecurityGroupId").MustStringArray()
			priority := 0
			for _, securityGroupId := range securityGroupIds {
				retSecurityGroup := model.VMSecurityGroup{
					Lcuuid:              common.GenerateUUIDByOrgID(a.orgID, vmLcuuid+securityGroupId),
					VMLcuuid:            vmLcuuid,
					SecurityGroupLcuuid: common.GenerateUUIDByOrgID(a.orgID, securityGroupId),
					Priority:            priority,
				}
				retVMSecurityGroups = append(retVMSecurityGroups, retSecurityGroup)
			}

			// VM PublicIPs
			publicIPs := vm.Get("PublicIpAddress").Get("IpAddress").MustStringArray()
			for _, publicIP := range publicIPs {
				vinterfaceLcuuid := common.GenerateUUIDByOrgID(a.orgID, vmLcuuid+publicIP)
				retVInterface := model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  vmLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     VPCLcuuid,
					RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				ipLcuuid := common.GenerateUUIDByOrgID(a.orgID, vinterfaceLcuuid+publicIP)
				retIP := model.IP{
					Lcuuid:           ipLcuuid,
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               publicIP,
					RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
				}
				retIPs = append(retIPs, retIP)

				floatingIPLcuuid := common.GenerateUUIDByOrgID(a.orgID, vmLcuuid+publicIP)
				retFloatingIP := model.FloatingIP{
					Lcuuid:        floatingIPLcuuid,
					IP:            publicIP,
					VMLcuuid:      vmLcuuid,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     VPCLcuuid,
					RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
				}
				retFloatingIPs = append(retFloatingIPs, retFloatingIP)
			}
		}
	}
	log.Debug("get vms complete")
	return retVMs, retVMSecurityGroups, retVInterfaces, retIPs, retFloatingIPs, vmLcuuidToVPCLcuuid, nil
}

func (a *Aliyun) getVMPorts(region model.Region) ([]model.VInterface, []model.IP, []model.FloatingIP, []model.NATRule, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP
	var retNATRules []model.NATRule

	log.Debug("get ports starting")
	request := ecs.CreateDescribeNetworkInterfacesRequest()
	response, err := a.getVMInterfaceResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retVInterfaces, retIPs, retFloatingIPs, retNATRules, nil
	}

	for _, r := range response {
		ports, _ := r.Get("NetworkInterfaceSet").Array()
		for i := range ports {
			port := r.Get("NetworkInterfaceSet").GetIndex(i)

			err := a.checkRequiredAttributes(
				port,
				[]string{"NetworkInterfaceId", "MacAddress", "InstanceId", "VSwitchId", "VpcId"},
			)
			if err != nil {
				log.Info(err)
				continue
			}

			instanceId := port.Get("InstanceId").MustString()
			if instanceId == "" || !strings.HasPrefix(instanceId, "i-") {
				continue
			}

			portLcuuid := common.GenerateUUIDByOrgID(a.orgID, port.Get("NetworkInterfaceId").MustString())
			deviceLcuuid := common.GenerateUUIDByOrgID(a.orgID, instanceId)
			networkLcuuid := common.GenerateUUIDByOrgID(a.orgID, port.Get("VSwitchId").MustString())
			vpcLcuuid := common.GenerateUUIDByOrgID(a.orgID, port.Get("VpcId").MustString())
			mac := port.Get("MacAddress").MustString()
			retVInterface := model.VInterface{
				Lcuuid:        portLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           mac,
				DeviceLcuuid:  deviceLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			// IP地址
			ips := port.Get("PrivateIpSets").Get("PrivateIpSet").MustArray()
			for i := range ips {
				// 内网IP
				ip := port.Get("PrivateIpSets").Get("PrivateIpSet").GetIndex(i)

				// 阿里公有云过滤直接用于POD的网卡(Primary && Secondary)
				if port.Get("Description").MustString() == "created by Container Service" {
					continue
				}
				privateIP := ip.Get("PrivateIpAddress").MustString()
				if privateIP == "" {
					continue
				}
				retIP := model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, portLcuuid+privateIP),
					VInterfaceLcuuid: portLcuuid,
					IP:               privateIP,
					SubnetLcuuid:     common.GenerateUUIDByOrgID(a.orgID, networkLcuuid),
					RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
				}
				retIPs = append(retIPs, retIP)

				// 公网IP
				publicIP := ip.Get("AssociatedPublicIp").Get("PublicIpAddress").MustString()
				if publicIP == "" {
					continue
				}
				publicPortLcuuid := common.GenerateUUIDByOrgID(a.orgID, portLcuuid)
				retVInterface := model.VInterface{
					Lcuuid:        publicPortLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           "ff" + mac[2:],
					DeviceLcuuid:  deviceLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				retIP = model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, deviceLcuuid+publicIP),
					VInterfaceLcuuid: publicPortLcuuid,
					IP:               publicIP,
					RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
				}
				retIPs = append(retIPs, retIP)

				floatingIPLcuuid := common.GenerateUUIDByOrgID(a.orgID, deviceLcuuid+publicIP)
				retFloatingIP := model.FloatingIP{
					Lcuuid:        floatingIPLcuuid,
					IP:            publicIP,
					VMLcuuid:      deviceLcuuid,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
				}
				retFloatingIPs = append(retFloatingIPs, retFloatingIP)

				retNATRule := model.NATRule{
					Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, publicIP+"_"+privateIP),
					Type:             "DNAT",
					Protocol:         "ALL",
					FloatingIP:       publicIP,
					FixedIP:          privateIP,
					VInterfaceLcuuid: portLcuuid,
				}
				retNATRules = append(retNATRules, retNATRule)
			}
		}
	}
	log.Debug("get ports complete")
	return retVInterfaces, retIPs, retFloatingIPs, retNATRules, nil
}
