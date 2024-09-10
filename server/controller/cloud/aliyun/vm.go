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
	simplejson "github.com/bitly/go-simplejson"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aliyun) getVMs(region model.Region, rgIDs []string) (
	[]model.VM, []model.VInterface, []model.IP, []model.FloatingIP, map[string]string, error,
) {
	var retVMs []model.VM
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP
	var vmLcuuidToVPCLcuuid = make(map[string]string)

	log.Debug("get vms starting", logger.NewORGPrefix(a.orgID))

	var responses []*simplejson.Json
	if len(rgIDs) == 0 {
		request := ecs.CreateDescribeInstancesRequest()
		vmResponses, err := a.getVMResponse(region.Label, request)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(a.orgID))
			return retVMs, retVInterfaces, retIPs, retFloatingIPs, vmLcuuidToVPCLcuuid, err
		}
		responses = append(responses, vmResponses...)
	} else {
		// remove duplicate ResourceGroupId
		rgIDMap := map[string]bool{}
		for _, rgID := range rgIDs {
			rgIDMap[rgID] = false
		}
		for rgID := range rgIDMap {
			log.Debugf("get instance for regin (%s) resource (%s)", region.Label, rgID, logger.NewORGPrefix(a.orgID))
			request := ecs.CreateDescribeInstancesRequest()
			request.ResourceGroupId = rgID
			vmResponses, err := a.getVMResponse(region.Label, request)
			if err != nil {
				log.Error(err, logger.NewORGPrefix(a.orgID))
				return retVMs, retVInterfaces, retIPs, retFloatingIPs, vmLcuuidToVPCLcuuid, err
			}
			responses = append(responses, vmResponses...)
		}
	}

	for _, r := range responses {
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
				log.Infof("no vpcId in vm (%s) data", vmId, logger.NewORGPrefix(a.orgID))
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

			cloudTags := map[string]string{}
			vmTags := vm.GetPath("Tags", "Tag")
			for t := range vmTags.MustArray() {
				tag := vmTags.GetIndex(t)
				cloudTags[tag.Get("TagKey").MustString()] = tag.Get("TagValue").MustString()
			}

			retVM := model.VM{
				Lcuuid:       vmLcuuid,
				Name:         vmName,
				Label:        vmId,
				HType:        common.VM_HTYPE_VM_C,
				VPCLcuuid:    VPCLcuuid,
				State:        vmState,
				IP:           pIP,
				CloudTags:    cloudTags,
				CreatedAt:    createdAt,
				AZLcuuid:     common.GenerateUUIDByOrgID(a.orgID, a.uuidGenerate+"_"+zoneId),
				RegionLcuuid: a.regionLcuuid,
			}
			retVMs = append(retVMs, retVM)
			a.azLcuuidToResourceNum[retVM.AZLcuuid]++

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
					RegionLcuuid:  a.regionLcuuid,
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				ipLcuuid := common.GenerateUUIDByOrgID(a.orgID, vinterfaceLcuuid+publicIP)
				retIP := model.IP{
					Lcuuid:           ipLcuuid,
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               publicIP,
					RegionLcuuid:     a.regionLcuuid,
				}
				retIPs = append(retIPs, retIP)

				floatingIPLcuuid := common.GenerateUUIDByOrgID(a.orgID, vmLcuuid+publicIP)
				retFloatingIP := model.FloatingIP{
					Lcuuid:        floatingIPLcuuid,
					IP:            publicIP,
					VMLcuuid:      vmLcuuid,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     VPCLcuuid,
					RegionLcuuid:  a.regionLcuuid,
				}
				retFloatingIPs = append(retFloatingIPs, retFloatingIP)
			}
		}
	}
	log.Debug("get vms complete", logger.NewORGPrefix(a.orgID))
	return retVMs, retVInterfaces, retIPs, retFloatingIPs, vmLcuuidToVPCLcuuid, nil
}

func (a *Aliyun) getVMPorts(region model.Region) ([]model.VInterface, []model.IP, []model.FloatingIP, []model.NATRule, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP
	var retNATRules []model.NATRule

	log.Debug("get ports starting", logger.NewORGPrefix(a.orgID))
	request := ecs.CreateDescribeNetworkInterfacesRequest()
	response, err := a.getVMInterfaceResponse(region.Label, request)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(a.orgID))
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
				log.Info(err, logger.NewORGPrefix(a.orgID))
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
				RegionLcuuid:  a.regionLcuuid,
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
					RegionLcuuid:     a.regionLcuuid,
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
					RegionLcuuid:  a.regionLcuuid,
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				retIP = model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, deviceLcuuid+publicIP),
					VInterfaceLcuuid: publicPortLcuuid,
					IP:               publicIP,
					RegionLcuuid:     a.regionLcuuid,
				}
				retIPs = append(retIPs, retIP)

				floatingIPLcuuid := common.GenerateUUIDByOrgID(a.orgID, deviceLcuuid+publicIP)
				retFloatingIP := model.FloatingIP{
					Lcuuid:        floatingIPLcuuid,
					IP:            publicIP,
					VMLcuuid:      deviceLcuuid,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  a.regionLcuuid,
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
	log.Debug("get ports complete", logger.NewORGPrefix(a.orgID))
	return retVInterfaces, retIPs, retFloatingIPs, retNATRules, nil
}
