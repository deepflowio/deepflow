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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/bcc"
	bcc_api "github.com/baidubce/bce-sdk-go/services/bcc/api"
	"github.com/baidubce/bce-sdk-go/services/eni"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getVMs(
	region model.Region, zoneNameToAZLcuuid map[string]string, vpcIdToLcuuid map[string]string,
	networkIdToLcuuid map[string]string,
) ([]model.VM, []model.VInterface, []model.IP, error) {
	var retVMs []model.VM
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var vmIdToLcuuid map[string]string

	log.Debug("get vms starting")

	bccClient, _ := bcc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	bccClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &bcc_api.ListInstanceArgs{}
	results := make([]*bcc_api.ListInstanceResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := bccClient.ListInstances(args)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListInstances", len(result.Instances), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListInstances", " ", structToJson(results))
	vmIdToLcuuid = make(map[string]string)
	for _, r := range results {
		for _, vm := range r.Instances {
			azLcuuid, ok := zoneNameToAZLcuuid[vm.ZoneName]
			if !ok {
				log.Debugf("vm (%s) az (%s) not found", vm.InstanceId, vm.ZoneName)
				continue
			}
			vpcLcuuid, ok := vpcIdToLcuuid[vm.VpcId]
			if !ok {
				log.Debugf("vm (%s) vpc (%s) not found", vm.InstanceId, vm.VpcId)
				continue
			}
			networkLcuuid, ok := networkIdToLcuuid[vm.SubnetId]
			if !ok {
				log.Debugf("vm (%s) network (%s) not found", vm.InstanceId, vm.SubnetId)
				continue
			}

			vmLcuuid := common.GenerateUUIDByOrgID(b.orgID, vm.InstanceId)
			vmState := common.VM_STATE_EXCEPTION
			if vm.Status == "Running" {
				vmState = common.VM_STATE_RUNNING
			} else if vm.Status == "Stopped" {
				vmState = common.VM_STATE_STOPPED
			}

			var pIP string
			for _, nic := range vm.NicInfo.Ips {
				if nic.Primary == "true" {
					pIP = nic.PrivateIp
					break
				}
			}

			retVM := model.VM{
				Lcuuid:       vmLcuuid,
				Name:         vm.InstanceName,
				Label:        vm.InstanceId,
				HType:        common.VM_HTYPE_VM_C,
				VPCLcuuid:    vpcLcuuid,
				State:        vmState,
				IP:           pIP,
				AZLcuuid:     azLcuuid,
				RegionLcuuid: region.Lcuuid,
			}
			retVMs = append(retVMs, retVM)
			vmIdToLcuuid[vm.InstanceId] = vmLcuuid
			b.azLcuuidToResourceNum[retVM.AZLcuuid]++
			b.regionLcuuidToResourceNum[retVM.RegionLcuuid]++

			// 虚拟机主网卡信息
			// 虚拟机API不会返回弹性网卡信息，需要通过弹性网卡API单独获取
			if vm.NicInfo.MacAddress == "" {
				continue
			}

			vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, vmLcuuid+vm.NicInfo.MacAddress)
			retVInterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           vm.NicInfo.MacAddress,
				DeviceLcuuid:  vmLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  region.Lcuuid,
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			for _, ip := range vm.NicInfo.Ips {
				if ip.PrivateIp == "" {
					continue
				}
				// 内网IP
				ipLcuuid := common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+ip.PrivateIp)
				retIP := model.IP{
					Lcuuid:           ipLcuuid,
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip.PrivateIp,
					SubnetLcuuid:     common.GenerateUUIDByOrgID(b.orgID, networkLcuuid),
					RegionLcuuid:     region.Lcuuid,
				}
				retIPs = append(retIPs, retIP)

				// 公网接口 + IP
				if ip.Eip == "" || ip.Eip == "null" {
					continue
				}
				publicVInterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, vmLcuuid+ip.Eip)
				retVInterface = model.VInterface{
					Lcuuid:        publicVInterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  vmLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  region.Lcuuid,
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				publicIPLcuuid := common.GenerateUUIDByOrgID(b.orgID, publicVInterfaceLcuuid+ip.Eip)
				retIP = model.IP{
					Lcuuid:           publicIPLcuuid,
					VInterfaceLcuuid: publicVInterfaceLcuuid,
					IP:               ip.Eip,
					RegionLcuuid:     region.Lcuuid,
				}
				retIPs = append(retIPs, retIP)
			}
		}
	}

	// 获取弹性网卡及IP信息
	tmpVInterfaces, tmpIPs, err := b.getVMEnis(region, vpcIdToLcuuid, networkIdToLcuuid, vmIdToLcuuid)
	if err != nil {
		return nil, nil, nil, err
	}

	retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
	retIPs = append(retIPs, tmpIPs...)

	log.Debug("get vms complete")
	return retVMs, retVInterfaces, retIPs, nil
}

func (b *BaiduBce) getVMEnis(
	region model.Region, vpcIdToLcuuid map[string]string, networkIdToLcuuid map[string]string, vmIdToLcuuid map[string]string,
) ([]model.VInterface, []model.IP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get vm enis starting")

	eniClient, _ := eni.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	eniClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	for vpcId, vpcLcuuid := range vpcIdToLcuuid {
		marker := ""
		args := &eni.ListEniArgs{VpcId: vpcId}
		results := make([]*eni.ListEniResult, 0)
		for {
			args.Marker = marker
			startTime := time.Now()
			result, err := eniClient.ListEni(args)
			if err != nil {
				log.Error(err)
				return nil, nil, err
			}
			b.cloudStatsd.RefreshAPIMoniter("ListEni", len(result.Eni), startTime)
			results = append(results, result)
			if !result.IsTruncated {
				break
			}
			marker = result.NextMarker
		}

		b.debugger.WriteJson("ListEni", " ", structToJson(results))
		for _, r := range results {
			for _, eni := range r.Eni {
				// 未挂载虚拟机的弹性网卡不学习
				if eni.InstanceId == "" {
					continue
				}

				vmLcuuid, ok := vmIdToLcuuid[eni.InstanceId]
				if !ok {
					log.Infof("eni (%s) vm (%s) not found", eni.EniId, eni.InstanceId)
					continue
				}
				networkLcuuid, ok := networkIdToLcuuid[eni.SubnetId]
				if !ok {
					log.Infof("eni (%s) network (%s) not found", eni.EniId, eni.SubnetId)
					continue
				}

				vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, vmLcuuid+eni.EniId)
				retVInterface := model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.NETWORK_TYPE_LAN,
					Mac:           eni.MacAddress,
					DeviceLcuuid:  vmLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  region.Lcuuid,
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				for _, privateIP := range eni.PrivateIpSet {
					if privateIP.PrivateIpAddress == "" {
						continue
					}
					retIP := model.IP{
						Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+privateIP.PrivateIpAddress),
						VInterfaceLcuuid: vinterfaceLcuuid,
						IP:               privateIP.PrivateIpAddress,
						SubnetLcuuid:     common.GenerateUUIDByOrgID(b.orgID, networkLcuuid),
						RegionLcuuid:     region.Lcuuid,
					}
					retIPs = append(retIPs, retIP)

					// 公网IP
					if privateIP.PublicIpAddress == "" {
						continue
					}

					publicVInterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, vmLcuuid+privateIP.PublicIpAddress)
					retVInterface = model.VInterface{
						Lcuuid:        publicVInterfaceLcuuid,
						Type:          common.NETWORK_TYPE_WAN,
						Mac:           common.VIF_DEFAULT_MAC,
						DeviceLcuuid:  vmLcuuid,
						DeviceType:    common.VIF_DEVICE_TYPE_VM,
						NetworkLcuuid: common.NETWORK_ISP_LCUUID,
						VPCLcuuid:     vpcLcuuid,
						RegionLcuuid:  region.Lcuuid,
					}
					retVInterfaces = append(retVInterfaces, retVInterface)

					retIP = model.IP{
						Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, publicVInterfaceLcuuid+privateIP.PublicIpAddress),
						VInterfaceLcuuid: publicVInterfaceLcuuid,
						IP:               privateIP.PublicIpAddress,
						RegionLcuuid:     region.Lcuuid,
					}
					retIPs = append(retIPs, retIP)
				}
			}
		}
	}
	log.Debug("Get vm enis complete")
	return retVInterfaces, retIPs, nil
}
