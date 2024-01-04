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

package qingcloud

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/mikioh/ipaddr"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetVMs() ([]model.VM, []model.VMSecurityGroup, []model.Subnet, error) {
	var retVMs []model.VM
	var retVMSecurityGroups []model.VMSecurityGroup
	var retDefaultVxnetSubnets []model.Subnet
	var defaultVxnetIDs []string
	var vxnetIdToSubnetLcuuid map[string]string
	var vxnetIdToVPCLcuuid map[string]string
	var vmIdToVPCLcuuid map[string]string

	log.Info("get vms starting")

	vmIdToVPCLcuuid = make(map[string]string)
	vxnetIdToSubnetLcuuid = make(map[string]string)
	vxnetIdToVPCLcuuid = make(map[string]string)
	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "running"},
			{"status.2", "stopped"},
		}
		response, err := q.GetResponse("DescribeInstances", "instance_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				vm := r.GetIndex(i)
				err := q.CheckRequiredAttributes(vm, []string{
					"instance_id", "create_time", "status", "vxnets",
				})
				if err != nil {
					continue
				}

				// 根据虚拟机的网络信息确定所在的VPC
				// 根据基础网络中虚拟机，生成对应的网段信息
				vpcLcuuid, tmpDefaultVxnetSubnets, tmpDefaultVxnetIDs,
					tmpVxnetIdToSubnetLcuuid, err := q.getVMVPCLcuuid(regionId, regionLcuuid, vm)
				if err != nil {
					log.Infof("get vm (%s) vpc faild", vm.Get("instance_id").MustString())
					continue
				}
				retDefaultVxnetSubnets = append(retDefaultVxnetSubnets, tmpDefaultVxnetSubnets...)
				defaultVxnetIDs = append(defaultVxnetIDs, tmpDefaultVxnetIDs...)
				for vxnetId, subnetLcuuid := range tmpVxnetIdToSubnetLcuuid {
					vxnetIdToSubnetLcuuid[vxnetId] = subnetLcuuid
				}
				for _, vxnetId := range tmpDefaultVxnetIDs {
					vxnetIdToVPCLcuuid[vxnetId] = vpcLcuuid
				}

				vmId := vm.Get("instance_id").MustString()
				vmName := vm.Get("instance_name").MustString()
				if vmName == "" {
					vmName = vmId
				}
				// 仅针对私有云判断launch_server
				hostName := vm.Get("host_machine").MustString()
				launchServer := ""
				if !q.isPublicCloud {
					hostIP, ok := q.HostNameToIP[hostName]
					if !ok {
						log.Infof("vm (%s) host ip not found", vmId)
						continue
					}
					launchServer = hostIP
				}

				vmLcuuid := common.GenerateUUID(vmId)
				vmState := common.VM_STATE_EXCEPTION
				status := vm.Get("status").MustString()
				if status == "running" {
					vmState = common.VM_STATE_RUNNING
				} else if status == "stopped" {
					vmState = common.VM_STATE_STOPPED
				}
				azLcuuid := common.GenerateUUID(
					q.UuidGenerate + "_" + vm.Get("zone_id").MustString(),
				)
				retVMs = append(retVMs, model.VM{
					Lcuuid:       vmLcuuid,
					Name:         vmName,
					Label:        vmId,
					State:        vmState,
					HType:        common.VM_HTYPE_VM_C,
					LaunchServer: launchServer,
					VPCLcuuid:    vpcLcuuid,
					AZLcuuid:     azLcuuid,
					RegionLcuuid: regionLcuuid,
				})
				vmIdToVPCLcuuid[vmId] = vpcLcuuid
				q.azLcuuidToResourceNum[azLcuuid]++
				q.regionLcuuidToResourceNum[regionLcuuid]++

				// 虚拟机与安全组关联关系
				securityGroupId := vm.Get("security_group").Get("security_group_id").MustString()
				if securityGroupId == "" {
					continue
				}
				retVMSecurityGroups = append(
					retVMSecurityGroups,
					model.VMSecurityGroup{
						Lcuuid:              common.GenerateUUID(vmId + securityGroupId),
						SecurityGroupLcuuid: common.GenerateUUID(securityGroupId),
						VMLcuuid:            vmLcuuid,
						Priority:            1,
					},
				)
			}
		}
	}

	sort.Strings(defaultVxnetIDs)
	q.defaultVxnetIDs = defaultVxnetIDs
	q.vmIdToVPCLcuuid = vmIdToVPCLcuuid
	for vxnetId, subnetLcuuid := range vxnetIdToSubnetLcuuid {
		q.VxnetIdToSubnetLcuuid[vxnetId] = subnetLcuuid
	}
	for vxnetId, vpcLcuuid := range vxnetIdToVPCLcuuid {
		q.VxnetIdToVPCLcuuid[vxnetId] = vpcLcuuid
	}
	log.Info("get vms complete")
	return retVMs, retVMSecurityGroups, retDefaultVxnetSubnets, nil
}

func (q *QingCloud) getVMVPCLcuuid(regionId, regionLcuuid string, vm *simplejson.Json) (
	string, []model.Subnet, []string, map[string]string, error,
) {
	var retVPCLcuuid string
	var retDefaultVxnetSubnets []model.Subnet
	var retDefaultVxnetIDs []string
	var retVxnetIdToSubnetLcuuid map[string]string

	retVPCLcuuid, ok := q.regionIdToDefaultVPCLcuuid[regionId]
	if !ok {
		err := errors.New(fmt.Sprintf("(%s) default vpc not found", regionId))
		log.Info(err)
		return retVPCLcuuid, nil, nil, nil, err
	}

	retVxnetIdToSubnetLcuuid = make(map[string]string)
	for i := range vm.Get("vxnets").MustArray() {
		vxnet := vm.Get("vxnets").GetIndex(i)

		vxnetName := vxnet.Get("vxnet_name").MustString()
		vxnetId := vxnet.Get("vxnet_id").MustString()
		if vxnetName == q.defaultVxnetName {
			subnetLcuuid := common.GenerateUUID(vxnetId)
			privateIP := vxnet.Get("private_ip").MustString()
			if privateIP != "" {
				cidrParse, _ := ipaddr.Parse(
					privateIP + "/" + strconv.Itoa(common.IPV4_DEFAULT_NETMASK),
				)
				subnetCidr := cidrParse.First().IP.String() + "/" +
					strconv.Itoa(common.IPV4_DEFAULT_NETMASK)
				retDefaultVxnetSubnets = append(
					retDefaultVxnetSubnets,
					model.Subnet{
						Lcuuid:        subnetLcuuid,
						Name:          vxnetName,
						CIDR:          subnetCidr,
						NetworkLcuuid: common.GenerateUUID(vxnetName + regionLcuuid),
						VPCLcuuid:     retVPCLcuuid,
					},
				)
			}
			retDefaultVxnetIDs = append(retDefaultVxnetIDs, vxnetId)
			retVxnetIdToSubnetLcuuid[vxnetId] = subnetLcuuid
		} else {
			vpcLcuuid, ok := q.VxnetIdToVPCLcuuid[vxnetId]
			if !ok {
				log.Debugf(
					"vm (%s) vxnetId (%s) vpc not found",
					vm.Get("instance_id").MustString(), vxnetId,
				)
			} else {
				retVPCLcuuid = vpcLcuuid
			}
		}
	}
	return retVPCLcuuid, retDefaultVxnetSubnets, retDefaultVxnetIDs,
		retVxnetIdToSubnetLcuuid, nil
}

func (q *QingCloud) GetVMNics() ([]model.VInterface, []model.IP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Info("get vm nics starting")

	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "in-use"},
		}
		response, err := q.GetResponse("DescribeNics", "nic_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				nic := r.GetIndex(i)

				nicId := nic.Get("nic_id").MustString()
				instanceId := nic.Get("instance_id").MustString()
				if instanceId == "" {
					log.Debugf("nic (%s) instance_id is null", nicId)
					continue
				}
				vpcLcuuid, ok := q.vmIdToVPCLcuuid[instanceId]
				if !ok {
					log.Debugf("nic (%s) instance_id (%s) vpc not found", nicId, instanceId)
					continue
				}
				// 如果接口属于基础网络，则生成基础网络对应的NetworkLcuuid
				vxnetId := nic.Get("vxnet_id").MustString()
				if vxnetId == "" {
					log.Infof("nic (%s) vxnet_id is null", nicId)
					continue
				}
				networkLcuuid := common.GenerateUUID(vxnetId)
				netType := common.VIF_TYPE_LAN
				index := sort.SearchStrings(q.defaultVxnetIDs, vxnetId)
				if index < len(q.defaultVxnetIDs) && q.defaultVxnetIDs[index] == vxnetId {
					networkLcuuid = common.GenerateUUID(q.defaultVxnetName + regionLcuuid)
					netType = common.VIF_TYPE_WAN
				} else if _, ok := q.VxnetIdToVPCLcuuid[vxnetId]; !ok {
					networkLcuuid = common.NETWORK_ISP_LCUUID
					netType = common.VIF_TYPE_WAN
				}

				vinterfaceLcuuid := common.GenerateUUID(nicId + instanceId)
				retVInterfaces = append(retVInterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Name:          nic.Get("nic_name").MustString(),
					Type:          netType,
					Mac:           nicId,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					DeviceLcuuid:  common.GenerateUUID(instanceId),
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  regionLcuuid,
				})

				// 生成内网IP
				privateIP := nic.Get("private_ip").MustString()
				if privateIP != "" {
					subnetLcuuid, ok := q.VxnetIdToSubnetLcuuid[vxnetId]
					if ok {
						retIPs = append(retIPs, model.IP{
							Lcuuid: common.GenerateUUID(
								nicId + privateIP + strconv.Itoa(common.NETWORK_TYPE_LAN),
							),
							VInterfaceLcuuid: vinterfaceLcuuid,
							IP:               privateIP,
							SubnetLcuuid:     subnetLcuuid,
							RegionLcuuid:     regionLcuuid,
						})
					}
				}
				// 生成公网IP
				publicIP := nic.Get("eip").Get("eip_addr").MustString()
				if publicIP != "" {
					publicVInterfaceLcuuid := common.GenerateUUID(vinterfaceLcuuid)
					retVInterfaces = append(retVInterfaces, model.VInterface{
						Lcuuid:        publicVInterfaceLcuuid,
						Type:          common.VIF_TYPE_WAN,
						Mac:           "ff" + nicId[2:],
						DeviceType:    common.VIF_DEVICE_TYPE_VM,
						DeviceLcuuid:  common.GenerateUUID(instanceId),
						NetworkLcuuid: common.NETWORK_ISP_LCUUID,
						VPCLcuuid:     vpcLcuuid,
						RegionLcuuid:  regionLcuuid,
					})
					retIPs = append(retIPs, model.IP{
						Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + publicIP),
						VInterfaceLcuuid: publicVInterfaceLcuuid,
						IP:               publicIP,
						RegionLcuuid:     regionLcuuid,
					})
				}
			}
		}
	}
	log.Info("get vm nics complete")
	return retVInterfaces, retIPs, nil
}
