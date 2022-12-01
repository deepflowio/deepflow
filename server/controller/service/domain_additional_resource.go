/*
 * Copyright (c) 2022 Yunshan Networks
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

package service

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/model"
	"gorm.io/gorm"
)

func ApplyDomainAddtionalResource(reqData map[string][]model.AdditionalResourceDomain) error {
	log.Infof("apply domain addtional resources: %#v", reqData)
	domains, err := formatData(reqData)
	if err != nil {
		return err
	}

	var dbItems []mysql.DomainAdditionalResource
	for _, domain := range domains {
		var dbDomain mysql.Domain
		err := mysql.Db.Where("lcuuid = ?", domain.Lcuuid).Take(&dbDomain).Error
		if err != nil {
			return NewError(
				common.RESOURCE_NOT_FOUND,
				fmt.Sprintf("domain (lcuuid: %s) not found in db: %s", domain.Lcuuid, err.Error()),
			)
		}
		if len(domain.AZs) == 0 && len(domain.VPCs) == 0 && len(domain.Networks) == 0 && len(domain.Hosts) == 0 && len(domain.VMs) == 0 {
			log.Info("domain (lcuuid: %s) has no additional resources to apply", domain.Lcuuid)
			continue
		}
		content, err := json.Marshal(domain)
		if err != nil {
			return NewError(
				common.SERVER_ERROR,
				fmt.Sprintf("json marshal (%#v) failed: %s", domain, err.Error()),
			)
		}
		dbItem := mysql.DomainAdditionalResource{
			Domain:  domain.Lcuuid,
			Content: string(content),
		}
		dbItems = append(dbItems, dbItem)
	}

	// Full update, delete all data before inserting
	err = mysql.Db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DomainAdditionalResource{}).Error
	if err != nil {
		return NewError(
			common.SERVER_ERROR,
			fmt.Sprintf("apply domain additional resources failed: %s", err.Error()),
		)
	}
	err = mysql.Db.Create(&dbItems).Error
	if err != nil {
		return NewError(
			common.SERVER_ERROR,
			fmt.Sprintf("apply domain additional resources failed: %s", err.Error()),
		)
	}
	return nil
}

func formatData(data map[string][]model.AdditionalResourceDomain) ([]model.AdditionalResourceDomain, error) {
	for _, domain := range data["domains"] {
		azLcuuids, err := getDomainAZLcuuidsIncludingDBData(domain)
		if err != nil {
			return nil, err
		}
		vpcLcuuids, err := getDomainVPCLcuuidsIncludingDBData(domain)
		if err != nil {
			return nil, err
		}
		networkLcuuidToNetType := make(map[string]int)
		subnetLcuuidToNetworkLcuuid := make(map[string]string)
		for _, network := range domain.Networks {
			if network.AZLcuuid != "" && !common.Contains(azLcuuids, network.AZLcuuid) {
				return nil, NewError(
					common.INVALID_POST_DATA,
					fmt.Sprintf("domain (lcuuid: %s) network (lcuuid: %s) az lcuuid: %s not found",
						domain.Lcuuid, network.Lcuuid, network.AZLcuuid,
					),
				)
			}
			if !common.Contains(vpcLcuuids, network.VPCLcuuid) {
				return nil, NewError(
					common.INVALID_POST_DATA,
					fmt.Sprintf("domain (lcuuid: %s) network (lcuuid: %s) vpc lcuuid: %s not found",
						domain.Lcuuid, network.Lcuuid, network.VPCLcuuid,
					),
				)
			}
			networkLcuuidToNetType[network.Lcuuid] = network.NetType
			for i := range network.Subnets {
				formattedCIDR := formatCIDR(network.Subnets[i].CIDR)
				if formattedCIDR == "" {
					return nil, NewError(
						common.INVALID_PARAMETERS,
						fmt.Sprintf("domain (lcuuid: %s) network (lcuuid: %s) subnet (lcuuid: %s) cidr: %s is invalid",
							domain.Lcuuid, network.Lcuuid, network.Subnets[i].Lcuuid, network.Subnets[i].CIDR,
						),
					)
				}
				network.Subnets[i].NetworkLcuuid = network.Lcuuid
				network.Subnets[i].VPCLcuuid = network.VPCLcuuid
				subnetLcuuidToNetworkLcuuid[network.Subnets[i].Lcuuid] = network.Subnets[i].NetworkLcuuid
			}
		}

		for _, host := range domain.Hosts {
			if !common.Contains(azLcuuids, host.AZLcuuid) {
				return nil, NewError(
					common.INVALID_POST_DATA,
					fmt.Sprintf("domain (lcuuid: %s) host (lcuuid: %s) az lcuuid: %s not found",
						domain.Lcuuid, host.Lcuuid, host.AZLcuuid,
					),
				)
			}
			host.Type = common.HOST_TYPE_VM
			if host.HType == 0 {
				host.HType = common.HOST_HTYPE_KVM
			}
			for vifIndex := range host.VInterfaces {
				if len(host.VInterfaces[vifIndex].IPs) == 0 {
					return nil, NewError(
						common.INVALID_POST_DATA,
						fmt.Sprintf(
							"domain (lcuuid: %s) host (lcuuid: %s) vinterface (mac: %s) has no ips",
							domain.Lcuuid, host.Lcuuid, host.VInterfaces[vifIndex].Mac,
						),
					)
				}
				host.VInterfaces[vifIndex].Lcuuid = common.GenerateUUID(domain.Lcuuid + host.VInterfaces[vifIndex].Mac)
				var networkLcuuid string
				for ipIndex := range host.VInterfaces[vifIndex].IPs {
					formattedIP := formatIP(host.VInterfaces[vifIndex].IPs[ipIndex].IP)
					if formattedIP == "" {
						return nil, NewError(
							common.INVALID_PARAMETERS,
							fmt.Sprintf("domain (lcuuid: %s) host (lcuuid: %s) vinterface (mac: %s) ip: %s is invalid",
								domain.Lcuuid, host.Lcuuid, host.VInterfaces[vifIndex].Mac, host.VInterfaces[vifIndex].IPs[ipIndex].IP,
							),
						)
					}
					host.VInterfaces[vifIndex].IPs[ipIndex].IP = formattedIP
					networkLcuuidTmp, ok := subnetLcuuidToNetworkLcuuid[host.VInterfaces[vifIndex].IPs[ipIndex].SubnetLcuuid]
					if !ok {
						return nil, NewError(
							common.RESOURCE_NOT_FOUND,
							fmt.Sprintf("domain (lcuuid: %s) host (lcuuid: %s) vinterface (mac: %s) ip: %#v subnet not found",
								domain.Lcuuid, host.Lcuuid, host.VInterfaces[vifIndex].Mac, host.VInterfaces[vifIndex].IPs[ipIndex],
							),
						)
					}
					if networkLcuuid == "" {
						networkLcuuid = networkLcuuidTmp
					} else if networkLcuuidTmp != networkLcuuid {
						return nil, NewError(
							common.INVALID_POST_DATA,
							fmt.Sprintf("domain (lcuuid: %s) host (lcuuid: %s) vinterface (mac: %s) ips' subnets must be in same network",
								domain.Lcuuid, host.Lcuuid, host.VInterfaces[vifIndex].Mac,
							),
						)
					}
					host.VInterfaces[vifIndex].IPs[ipIndex].Lcuuid = common.GenerateUUID(host.VInterfaces[vifIndex].Lcuuid + host.VInterfaces[vifIndex].IPs[ipIndex].IP)
					host.VInterfaces[vifIndex].IPs[ipIndex].RegionLcuuid = host.RegionLcuuid
					host.VInterfaces[vifIndex].IPs[ipIndex].VInterfaceLcuuid = host.VInterfaces[vifIndex].Lcuuid
				}
				host.VInterfaces[vifIndex].NetworkLcuuid = networkLcuuid
				t, ok := networkLcuuidToNetType[host.VInterfaces[vifIndex].NetworkLcuuid]
				if !ok {
					return nil, NewError(
						common.RESOURCE_NOT_FOUND,
						fmt.Sprintf("domain (lcuuid: %s) host (lcuuid: %s) vinterface: %#v network not found",
							domain.Lcuuid, host.Lcuuid, host.VInterfaces[vifIndex],
						),
					)
				}
				host.VInterfaces[vifIndex].Type = t
				host.VInterfaces[vifIndex].DeviceType = common.VIF_DEVICE_TYPE_HOST
				host.VInterfaces[vifIndex].DeviceLcuuid = host.Lcuuid
				host.VInterfaces[vifIndex].RegionLcuuid = host.RegionLcuuid
			}
		}

		for _, vm := range domain.VMs {
			if !common.Contains(azLcuuids, vm.AZLcuuid) {
				return nil, NewError(
					common.INVALID_POST_DATA,
					fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) az lcuuid: %s not found",
						domain.Lcuuid, vm.Lcuuid, vm.AZLcuuid,
					),
				)
			}
			if !common.Contains(vpcLcuuids, vm.VPCLcuuid) {
				return nil, NewError(
					common.INVALID_POST_DATA,
					fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) vpc lcuuid: %s not found",
						domain.Lcuuid, vm.Lcuuid, vm.VPCLcuuid,
					),
				)
			}
			vm.State = common.VM_STATE_RUNNING
			if vm.HType == 0 {
				vm.HType = common.VM_HTYPE_VM_C
			}
			for vifIndex := range vm.VInterfaces {
				if len(vm.VInterfaces[vifIndex].IPs) == 0 {
					return nil, NewError(
						common.INVALID_POST_DATA,
						fmt.Sprintf(
							"domain (lcuuid: %s) vm (lcuuid: %s) vinterface (mac: %s) has no ips",
							domain.Lcuuid, vm.Lcuuid, vm.VInterfaces[vifIndex].Mac,
						),
					)
				}

				vm.VInterfaces[vifIndex].Lcuuid = common.GenerateUUID(domain.Lcuuid + vm.VInterfaces[vifIndex].Mac)
				var networkLcuuid string
				for ipIndex := range vm.VInterfaces[vifIndex].IPs {
					formattedIP := formatIP(vm.VInterfaces[vifIndex].IPs[ipIndex].IP)
					if formattedIP == "" {
						return nil, NewError(
							common.INVALID_PARAMETERS,
							fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) vinterface (mac: %s) ip: %s is invalid",
								domain.Lcuuid, vm.Lcuuid, vm.VInterfaces[vifIndex].Mac, vm.VInterfaces[vifIndex].IPs[ipIndex].IP,
							),
						)
					}
					vm.VInterfaces[vifIndex].IPs[ipIndex].IP = formattedIP
					networkLcuuidTmp, ok := subnetLcuuidToNetworkLcuuid[vm.VInterfaces[vifIndex].IPs[ipIndex].SubnetLcuuid]
					if !ok {
						return nil, NewError(
							common.RESOURCE_NOT_FOUND,
							fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) vinterface (mac: %s) ip: %#v subnet not found",
								domain.Lcuuid, vm.Lcuuid, vm.VInterfaces[vifIndex].Mac, vm.VInterfaces[vifIndex].IPs[ipIndex],
							),
						)
					}
					if networkLcuuid == "" {
						networkLcuuid = networkLcuuidTmp
					} else if networkLcuuidTmp != networkLcuuid {
						return nil, NewError(
							common.INVALID_POST_DATA,
							fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) vinterface (mac: %s) ips' subnets must be in same network",
								domain.Lcuuid, vm.Lcuuid, vm.VInterfaces[vifIndex].Mac,
							),
						)
					}
					vm.VInterfaces[vifIndex].IPs[ipIndex].Lcuuid = common.GenerateUUID(vm.VInterfaces[vifIndex].Lcuuid + vm.VInterfaces[vifIndex].IPs[ipIndex].IP)
					vm.VInterfaces[vifIndex].IPs[ipIndex].RegionLcuuid = vm.RegionLcuuid
					vm.VInterfaces[vifIndex].IPs[ipIndex].VInterfaceLcuuid = vm.VInterfaces[vifIndex].Lcuuid
				}
				vm.VInterfaces[vifIndex].NetworkLcuuid = networkLcuuid
				t, ok := networkLcuuidToNetType[vm.VInterfaces[vifIndex].NetworkLcuuid]
				if !ok {
					return nil, NewError(
						common.RESOURCE_NOT_FOUND,
						fmt.Sprintf("domain (lcuuid: %s) vm (lcuuid: %s) vinterface: %#v network not found",
							domain.Lcuuid, vm.Lcuuid, vm.VInterfaces[vifIndex],
						),
					)
				}
				vm.VInterfaces[vifIndex].Type = t
				vm.VInterfaces[vifIndex].DeviceType = common.VIF_DEVICE_TYPE_HOST
				vm.VInterfaces[vifIndex].DeviceLcuuid = vm.Lcuuid
				vm.VInterfaces[vifIndex].RegionLcuuid = vm.RegionLcuuid
			}
		}
	}
	return data["domains"], nil
}

func formatIP(ip string) string {
	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}
	return i.String()
}

func formatCIDR(cidr string) string {
	_, c, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return c.String()
}

func getDomainAZLcuuidsIncludingDBData(domain model.AdditionalResourceDomain) ([]string, error) {
	var azLcuuids []string
	var dbAZs []mysql.AZ
	err := mysql.Db.Where("domain = ?", domain.Lcuuid).Find(&dbAZs).Error
	if err != nil {
		return nil, NewError(
			common.SERVER_ERROR,
			fmt.Sprintf("check domain (lcuuid: %s) failed: %s", domain.Lcuuid, err.Error()),
		)
	}
	for _, a := range dbAZs {
		azLcuuids = append(azLcuuids, a.Lcuuid)
	}
	for _, a := range domain.AZs {
		azLcuuids = append(azLcuuids, a.Lcuuid)
	}
	return azLcuuids, nil
}

func getDomainVPCLcuuidsIncludingDBData(domain model.AdditionalResourceDomain) ([]string, error) {
	var vpcLcuuids []string
	var dbVPCs []mysql.VPC
	err := mysql.Db.Where("domain = ?", domain.Lcuuid).Find(&dbVPCs).Error
	if err != nil {
		return nil, NewError(
			common.SERVER_ERROR,
			fmt.Sprintf("check domain (lcuuid: %s) failed: %s", domain.Lcuuid, err.Error()),
		)
	}
	for _, v := range dbVPCs {
		vpcLcuuids = append(vpcLcuuids, v.Lcuuid)
	}
	for _, v := range domain.VPCs {
		vpcLcuuids = append(vpcLcuuids, v.Lcuuid)
	}
	return vpcLcuuids, nil
}
