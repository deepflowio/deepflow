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

package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	controllercommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
)

const (
	CLOUD_TAGS_RESOURCE_TYPE_CHOST  = "chost"
	CLOUD_TAGS_RESOURCE_TYPE_POD_NS = "pod_ns"
)

type addtionalResourceToolDataSet struct {
	regionUUID             string
	azUUIDs                []string
	vpcUUIDs               []string
	subnetUUIDToType       map[string]int
	subnetToCIDRToCIDRUUID map[string]map[string]string
	hostIPToUUID           map[string]string
	additionalAZs          []model.AdditionalResourceAZ
	additionalVPCs         []model.AdditionalResourceVPC
	additionalSubnets      []model.AdditionalResourceSubnet
	additionalHosts        []model.AdditionalResourceHost
	additionalCHosts       []model.AdditionalResourceChost
	cloudTagCHosts         []mysql.VM
	cloudTagPodNamespaces  []mysql.PodNamespace
	subdomainPodNamespaces []mysql.PodNamespace
	additionalLBs          []model.AdditionalResourceLB
}

func newAddtionalResourceToolDataSet(regionUUID string) *addtionalResourceToolDataSet {
	return &addtionalResourceToolDataSet{
		regionUUID:             regionUUID,
		subnetUUIDToType:       make(map[string]int),
		subnetToCIDRToCIDRUUID: make(map[string]map[string]string),
		hostIPToUUID:           make(map[string]string),
	}
}

func ApplyDomainAddtionalResource(reqData model.AdditionalResource) error {
	log.Infof("apply domain additional resource: %#v", reqData)
	domainUUIDToToolDataSet, err := generateToolDataSet(reqData)
	if err != nil {
		return err
	}
	domainUUIDToCloudModelData, err := generateCloudModelData(domainUUIDToToolDataSet)
	if err != nil {
		return err
	}
	dbItems, err := generateDataToInsertDB(domainUUIDToCloudModelData)
	if err != nil {
		return err
	}
	err = fullUpdateDB(dbItems)
	return err
}

func fullUpdateDB(dbItems []mysql.DomainAdditionalResource) error {
	err := mysql.Db.Transaction(func(tx *gorm.DB) error {
		// Full update, delete all data before inserting
		err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DomainAdditionalResource{}).Error
		if err != nil {
			return err
		}
		return tx.Create(&dbItems).Error
	})
	if err != nil {
		return servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("apply domain additional resources error: %s", err.Error()),
		)
	}

	log.Debugf("apply domain additional resources success: %#v", dbItems)
	return nil
}

func generateDataToInsertDB(domainUUIDToCloudModelData map[string]*cloudmodel.AdditionalResource) ([]mysql.DomainAdditionalResource, error) {
	var dbItems []mysql.DomainAdditionalResource
	for domainUUID, cloudMD := range domainUUIDToCloudModelData {
		content, err := json.Marshal(cloudMD)
		if err != nil {
			return nil, servicecommon.NewError(
				httpcommon.SERVER_ERROR,
				fmt.Sprintf("json marshal domain (uuid: %s) cloud data (detail: %#v) failed: %s", domainUUID, cloudMD, err.Error()),
			)
		}

		dbItem := mysql.DomainAdditionalResource{
			Domain:            domainUUID,
			CompressedContent: content,
		}
		dbItems = append(dbItems, dbItem)
	}
	return dbItems, nil
}

func generateToolDataSet(additionalRsc model.AdditionalResource) (map[string]*addtionalResourceToolDataSet, error) {
	domainUUIDs := getDomainUUIDsUsedByAdditionalResource(additionalRsc)

	domainUUIDToToolDataSet := make(map[string]*addtionalResourceToolDataSet)
	domainUUIDToRegionUUID, err := getRegionDataFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}

	for domainUUID, regionUUID := range domainUUIDToRegionUUID {
		domainUUIDToToolDataSet[domainUUID] = newAddtionalResourceToolDataSet(regionUUID)
	}

	domainUUIDToAZUUIDs, err := getAZDataFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	for domainUUID, azUUIDs := range domainUUIDToAZUUIDs {
		domainUUIDToToolDataSet[domainUUID].azUUIDs = azUUIDs
	}
	for _, az := range additionalRsc.AZs {
		toolDS, ok := domainUUIDToToolDataSet[az.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("az (name: %s) domain (uuid: %s) not found", az.Name, az.DomainUUID),
			)
		}
		toolDS.azUUIDs = append(toolDS.azUUIDs, az.UUID)
		toolDS.additionalAZs = append(toolDS.additionalAZs, az)
	}

	domainUUIDToVPCUUIDs, err := getVPCDataFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	for domainUUID, vpcUUIDs := range domainUUIDToVPCUUIDs {
		domainUUIDToToolDataSet[domainUUID].vpcUUIDs = vpcUUIDs
	}
	for _, vpc := range additionalRsc.VPCs {
		toolDS, ok := domainUUIDToToolDataSet[vpc.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("vpc (name: %s) domain (uuid: %s) not found", vpc.Name, vpc.DomainUUID),
			)
		}
		toolDS.vpcUUIDs = append(toolDS.vpcUUIDs, vpc.UUID)
		toolDS.additionalVPCs = append(toolDS.additionalVPCs, vpc)
	}

	domainUUIDToSubnetInfoMap, domainUUIDToSubnetCIDRInfoMap, err := getSubnetDataFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	for domainUUID, subnetUUIDToType := range domainUUIDToSubnetInfoMap {
		domainUUIDToToolDataSet[domainUUID].subnetUUIDToType = subnetUUIDToType
	}
	for domainUUID, subnetToCIDRToCIDRUUID := range domainUUIDToSubnetCIDRInfoMap {
		domainUUIDToToolDataSet[domainUUID].subnetToCIDRToCIDRUUID = subnetToCIDRToCIDRUUID
	}
	for _, subnet := range additionalRsc.Subnets {
		toolDS, ok := domainUUIDToToolDataSet[subnet.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("subnet (name: %s) domain (uuid: %s) not found", subnet.Name, subnet.DomainUUID),
			)
		}
		if subnet.AZUUID != "" && !common.Contains(toolDS.azUUIDs, subnet.AZUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("subnet (name: %s) az (uuid: %s) not found", subnet.Name, subnet.AZUUID),
			)
		}
		if !common.Contains(toolDS.vpcUUIDs, subnet.VPCUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("subnet (name: %s) vpc (uuid: %s) not found", subnet.Name, subnet.VPCUUID),
			)
		}
		netType := subnet.Type
		if netType == 0 {
			netType = common.NETWORK_TYPE_LAN
		}
		toolDS.subnetUUIDToType[subnet.UUID] = netType
		toolDS.additionalSubnets = append(toolDS.additionalSubnets, subnet)

		toolDS.subnetToCIDRToCIDRUUID[subnet.UUID] = make(map[string]string)
		for _, cidr := range subnet.CIDRs {
			cidr := formatCIDR(cidr)
			if cidr == "" {
				return nil, servicecommon.NewError(
					httpcommon.INVALID_PARAMETERS,
					fmt.Sprintf("subnet (name: %s) cidr: %s is invalid", subnet.Name, cidr),
				)
			}
			toolDS.subnetToCIDRToCIDRUUID[subnet.UUID][cidr] = common.GenerateUUID(subnet.UUID + cidr)
		}
	}

	domainUUIDToHostIPMap, err := getDataInfoFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	for domainUUID, hostIPMap := range domainUUIDToHostIPMap {
		domainUUIDToToolDataSet[domainUUID].hostIPToUUID = hostIPMap
	}
	for _, host := range additionalRsc.Hosts {
		toolDS, ok := domainUUIDToToolDataSet[host.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("host (name: %s) domain (uuid: %s) not found", host.Name, host.DomainUUID),
			)
		}
		if !common.Contains(toolDS.azUUIDs, host.AZUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("host (name: %s) az (uuid: %s) not found", host.Name, host.AZUUID),
			)
		}
		toolDS.hostIPToUUID[host.IP] = host.UUID
		toolDS.additionalHosts = append(toolDS.additionalHosts, host)
		for _, vif := range host.VInterfaces {
			if vif.SubnetUUID == "" {
				if len(vif.IPs) != 0 {
					return nil, servicecommon.NewError(
						httpcommon.RESOURCE_NOT_FOUND,
						fmt.Sprintf("host (name: %s) vinterface (mac: %s) subnet (uuid: %s) not found", host.Name, vif.Mac, vif.SubnetUUID),
					)
				}
				continue
			}
			if _, ok := toolDS.subnetUUIDToType[vif.SubnetUUID]; !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("host (name: %s) vinterface (mac: %s) subnet (uuid: %s) not found", host.Name, vif.Mac, vif.SubnetUUID),
				)
			}
			for _, ip := range vif.IPs {
				ip := formatIP(ip)
				if ip == "" {
					return nil, servicecommon.NewError(
						httpcommon.INVALID_PARAMETERS,
						fmt.Sprintf("host (name: %s) vinterface (mac: %s) ip: %s is invalid", host.Name, vif.Mac, ip),
					)
				}
			}
		}
	}

	for _, chost := range additionalRsc.CHosts {
		toolDS, ok := domainUUIDToToolDataSet[chost.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("chost (name: %s) domain (uuid: %s) not found", chost.Name, chost.DomainUUID),
			)
		}
		if !common.Contains(toolDS.azUUIDs, chost.AZUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("chost (name: %s) az (uuid: %s) not found", chost.Name, chost.AZUUID),
			)
		}
		if !common.Contains(toolDS.vpcUUIDs, chost.VPCUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("chost (name: %s) vpc (uuid: %s) not found", chost.Name, chost.VPCUUID),
			)
		}
		if _, ok := toolDS.hostIPToUUID[chost.HostIP]; !ok && chost.HostIP != "" {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("chost (name: %s) host (ip: %s) not found", chost.Name, chost.HostIP),
			)
		}
		toolDS.additionalCHosts = append(toolDS.additionalCHosts, chost)
		for _, vif := range chost.VInterfaces {
			if _, ok := toolDS.subnetUUIDToType[vif.SubnetUUID]; !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("chost (name: %s) vinterface (mac: %s) subnet (uuid: %s) not found", chost.Name, vif.Mac, vif.SubnetUUID),
				)
			}
		}
	}

	for _, lb := range additionalRsc.LB {
		toolDS, ok := domainUUIDToToolDataSet[lb.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("lb (name: %s) domain (uuid: %s) not found", lb.Name, lb.DomainUUID),
			)
		}
		if toolDS.regionUUID != lb.RegionUUID {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("lb (name: %s) domain (uuid: %s) region(: %s) not found", lb.Name, lb.DomainUUID, lb.RegionUUID),
			)
		}
		if !common.Contains(toolDS.vpcUUIDs, lb.VPCUUID) {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("chost (name: %s) vpc (uuid: %s) not found", lb.Name, lb.VPCUUID),
			)
		}
		for _, vif := range lb.VInterfaces {
			if _, ok := toolDS.subnetUUIDToType[vif.SubnetUUID]; !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("lb (name: %s) vinterface (mac: %s) subnet (uuid: %s) not found", lb.Name, vif.Mac, vif.SubnetUUID),
				)
			}
		}
		toolDS.additionalLBs = append(toolDS.additionalLBs, lb)
	}

	// handle chosts and pod_namespaces
	domainUUIDToCHostNameToInfo, err := getCHostsFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	domainUUIDToPodNSNameToInfo, err := getPodNamespaceFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}
	subdomainUUIDToPodNSNameToInfo, err := getPodNamespaceInSubdomainFromDB(domainUUIDs)
	if err != nil {
		return nil, err
	}

	for _, cloudTag := range additionalRsc.CloudTags {
		toolDS, ok := domainUUIDToToolDataSet[cloudTag.DomainUUID]
		if !ok {
			return nil, servicecommon.NewError(
				httpcommon.RESOURCE_NOT_FOUND,
				fmt.Sprintf("cloud tag (resource name: %s) domain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID),
			)
		}

		// add cloud tags to subdomain
		if cloudTag.SubDomainUUID != "" {
			if cloudTag.ResourceType != CLOUD_TAGS_RESOURCE_TYPE_POD_NS {
				return nil, servicecommon.NewError(
					httpcommon.INVALID_POST_DATA,
					fmt.Sprintf("cloud tag (resource type: %s) subdomain (uuid: %s) not support", cloudTag.ResourceType, cloudTag.SubDomainUUID),
				)
			}
			podNSNameToInfo, ok := subdomainUUIDToPodNSNameToInfo[cloudTag.SubDomainUUID]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("cloud tag subdomain (uuid: %s) not found", cloudTag.SubDomainUUID))
			}
			podNS, ok := podNSNameToInfo[cloudTag.ResourceName]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.INVALID_POST_DATA,
					fmt.Sprintf("cloud tag (resource name: %s) subdomain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID))
			}
			podNS.CloudTags, err = convertTagsToMap(cloudTag.Tags)
			if err != nil {
				return nil, err
			}
			toolDS.subdomainPodNamespaces = append(toolDS.subdomainPodNamespaces, podNS)

			continue
		}

		if cloudTag.ResourceType == CLOUD_TAGS_RESOURCE_TYPE_CHOST {
			chostNameToInfo, ok := domainUUIDToCHostNameToInfo[cloudTag.DomainUUID]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("cloud tag (resource name: %s) domain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID),
				)
			}
			chost, ok := chostNameToInfo[cloudTag.ResourceName]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.INVALID_POST_DATA,
					fmt.Sprintf("cloud tag (resource name: %s) domain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID))
			}
			chost.CloudTags, err = convertTagsToMap(cloudTag.Tags)
			if err != nil {
				return nil, err
			}
			toolDS.cloudTagCHosts = append(toolDS.cloudTagCHosts, chost)
		} else if cloudTag.ResourceType == CLOUD_TAGS_RESOURCE_TYPE_POD_NS {
			podNSNameToInfo, ok := domainUUIDToPodNSNameToInfo[cloudTag.DomainUUID]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.RESOURCE_NOT_FOUND,
					fmt.Sprintf("cloud tag (resource name: %s) domain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID))
			}
			podNS, ok := podNSNameToInfo[cloudTag.ResourceName]
			if !ok {
				return nil, servicecommon.NewError(
					httpcommon.INVALID_POST_DATA,
					fmt.Sprintf("cloud tag (resource name: %s) domain (uuid: %s) not found", cloudTag.ResourceName, cloudTag.DomainUUID))
			}
			podNS.CloudTags, err = convertTagsToMap(cloudTag.Tags)
			if err != nil {
				return nil, err
			}
			toolDS.cloudTagPodNamespaces = append(toolDS.cloudTagPodNamespaces, podNS)
		} else {
			return nil, servicecommon.NewError(
				httpcommon.INVALID_POST_DATA,
				fmt.Sprintf("cloud tag (resource type: %s) not support", cloudTag.ResourceType),
			)
		}
	}

	return domainUUIDToToolDataSet, nil
}

func getDomainUUIDsUsedByAdditionalResource(additionalRsc model.AdditionalResource) []string {
	domainUUIDs := mapset.NewSet[string]()
	for _, az := range additionalRsc.AZs {
		domainUUIDs.Add(az.DomainUUID)
	}
	for _, vpc := range additionalRsc.VPCs {
		domainUUIDs.Add(vpc.DomainUUID)
	}
	for _, subnet := range additionalRsc.Subnets {
		domainUUIDs.Add(subnet.DomainUUID)
	}
	for _, host := range additionalRsc.Hosts {
		domainUUIDs.Add(host.DomainUUID)
	}
	for _, chost := range additionalRsc.CHosts {
		domainUUIDs.Add(chost.DomainUUID)
	}
	for _, cloudTag := range additionalRsc.CloudTags {
		domainUUIDs.Add(cloudTag.DomainUUID)
	}
	for _, lb := range additionalRsc.LB {
		domainUUIDs.Add(lb.DomainUUID)
	}
	return domainUUIDs.ToSlice()
}

func generateCloudModelData(domainUUIDToToolDataSet map[string]*addtionalResourceToolDataSet) (map[string]*cloudmodel.AdditionalResource, error) {
	domainUUIDToCloudModelData := make(map[string]*cloudmodel.AdditionalResource)
	for domainUUID, toolDS := range domainUUIDToToolDataSet {
		cloudMD := &cloudmodel.AdditionalResource{}
		for _, az := range toolDS.additionalAZs {
			cloudMD.AZs = append(
				cloudMD.AZs,
				cloudmodel.AZ{
					Lcuuid:       az.UUID,
					Name:         az.Name,
					RegionLcuuid: toolDS.regionUUID,
				},
			)
		}
		for _, vpc := range toolDS.additionalVPCs {
			cloudMD.VPCs = append(
				cloudMD.VPCs,
				cloudmodel.VPC{
					Lcuuid:       vpc.UUID,
					Name:         vpc.Name,
					RegionLcuuid: toolDS.regionUUID,
				},
			)
		}
		for _, subnet := range toolDS.additionalSubnets {
			cloudMD.Subnets = append(
				cloudMD.Subnets,
				cloudmodel.Network{
					Lcuuid:       subnet.UUID,
					Name:         subnet.Name,
					NetType:      toolDS.subnetUUIDToType[subnet.UUID],
					VPCLcuuid:    subnet.VPCUUID,
					AZLcuuid:     subnet.AZUUID,
					RegionLcuuid: toolDS.regionUUID,
					IsVIP:        subnet.IsVIP,
				},
			)
			for _, cidr := range subnet.CIDRs {
				cloudMD.SubnetCIDRs = append(
					cloudMD.SubnetCIDRs,
					cloudmodel.Subnet{
						Lcuuid:        toolDS.subnetToCIDRToCIDRUUID[subnet.UUID][cidr],
						CIDR:          cidr,
						Name:          cidr,
						NetworkLcuuid: subnet.UUID,
						VPCLcuuid:     subnet.VPCUUID,
					},
				)
			}
		}
		for _, host := range toolDS.additionalHosts {
			htype := host.Type
			if htype == 0 {
				htype = common.HOST_HTYPE_KVM
			}
			cloudMD.Hosts = append(
				cloudMD.Hosts,
				cloudmodel.Host{
					Lcuuid:       host.UUID,
					Name:         host.Name,
					IP:           host.IP,
					Type:         common.HOST_TYPE_VM,
					HType:        htype,
					AZLcuuid:     host.AZUUID,
					RegionLcuuid: toolDS.regionUUID,
				},
			)
			for _, vif := range host.VInterfaces {
				vifUUID := common.GenerateUUID(vif.SubnetUUID + vif.Mac)
				cloudMD.VInterfaces = append(
					cloudMD.VInterfaces,
					cloudmodel.VInterface{
						Lcuuid:        vifUUID,
						Name:          vif.Name,
						Mac:           vif.Mac,
						Type:          toolDS.subnetUUIDToType[vif.SubnetUUID],
						DeviceType:    common.VIF_DEVICE_TYPE_HOST,
						DeviceLcuuid:  host.UUID,
						NetworkLcuuid: vif.SubnetUUID,
						RegionLcuuid:  toolDS.regionUUID,
					},
				)
				for _, ip := range vif.IPs {
					var subnetCIDRUUID string
					for cidr, uuid := range toolDS.subnetToCIDRToCIDRUUID[vif.SubnetUUID] {
						if isIPInCIDR(cidr, ip) {
							subnetCIDRUUID = uuid
							break
						}
					}
					if subnetCIDRUUID == "" {
						return nil, servicecommon.NewError(
							httpcommon.RESOURCE_NOT_FOUND,
							fmt.Sprintf("host (name: %s) vinterface (mac: %s) ip: %s is not in any cidr", host.Name, vif.Mac, ip),
						)
					}
					cloudMD.IPs = append(
						cloudMD.IPs,
						cloudmodel.IP{
							Lcuuid:           common.GenerateUUID(vifUUID + ip),
							IP:               ip,
							VInterfaceLcuuid: vifUUID,
							SubnetLcuuid:     subnetCIDRUUID,
							RegionLcuuid:     toolDS.regionUUID,
						},
					)
				}
			}
		}
		for _, chost := range toolDS.additionalCHosts {
			htype := chost.Type
			if htype == 0 {
				htype = common.VM_HTYPE_BM_C
			}
			cloudMD.CHosts = append(
				cloudMD.CHosts,
				cloudmodel.VM{
					Lcuuid:       chost.UUID,
					Name:         chost.Name,
					LaunchServer: chost.HostIP,
					HType:        htype,
					State:        common.VM_STATE_RUNNING,
					VPCLcuuid:    chost.VPCUUID,
					AZLcuuid:     chost.AZUUID,
					RegionLcuuid: toolDS.regionUUID,
				},
			)
			for _, vif := range chost.VInterfaces {
				vifUUID := common.GenerateUUID(vif.SubnetUUID + vif.Mac)
				cloudMD.VInterfaces = append(
					cloudMD.VInterfaces,
					cloudmodel.VInterface{
						Lcuuid:        vifUUID,
						Mac:           vif.Mac,
						Type:          toolDS.subnetUUIDToType[vif.SubnetUUID],
						DeviceType:    common.VIF_DEVICE_TYPE_VM,
						DeviceLcuuid:  chost.UUID,
						NetworkLcuuid: vif.SubnetUUID,
						RegionLcuuid:  toolDS.regionUUID,
					},
				)
				for _, ip := range vif.IPs {
					var subnetCIDRUUID string
					for cidr, uuid := range toolDS.subnetToCIDRToCIDRUUID[vif.SubnetUUID] {
						if isIPInCIDR(cidr, ip) {
							subnetCIDRUUID = uuid
							break
						}
					}
					if subnetCIDRUUID == "" {
						return nil, servicecommon.NewError(
							httpcommon.RESOURCE_NOT_FOUND,
							fmt.Sprintf("chost (name: %s) vinterface (mac: %s) ip: %s is not in any cidr", chost.Name, vif.Mac, ip),
						)
					}
					cloudMD.IPs = append(
						cloudMD.IPs,
						cloudmodel.IP{
							Lcuuid:           common.GenerateUUID(vifUUID + ip),
							IP:               ip,
							VInterfaceLcuuid: vifUUID,
							SubnetLcuuid:     subnetCIDRUUID,
							RegionLcuuid:     toolDS.regionUUID,
						},
					)
				}
			}
		}

		for _, chost := range toolDS.cloudTagCHosts {
			if cloudMD.CHostCloudTags == nil {
				cloudMD.CHostCloudTags = make(cloudmodel.UUIDToCloudTags)
			}
			cloudMD.CHostCloudTags[chost.Lcuuid] = chost.CloudTags
		}
		for _, podNamespace := range toolDS.cloudTagPodNamespaces {
			if cloudMD.PodNamespaceCloudTags == nil {
				cloudMD.PodNamespaceCloudTags = make(cloudmodel.UUIDToCloudTags)
			}
			cloudMD.PodNamespaceCloudTags[podNamespace.Lcuuid] = podNamespace.CloudTags
		}
		for _, podNamespace := range toolDS.subdomainPodNamespaces {
			if cloudMD.SubDomainResources == nil {
				cloudMD.SubDomainResources = make(map[string]*cloudmodel.AdditionalSubdomainResource)
			}
			if cloudMD.SubDomainResources[podNamespace.SubDomain] == nil {
				cloudMD.SubDomainResources[podNamespace.SubDomain] = &cloudmodel.AdditionalSubdomainResource{
					PodNamespaceCloudTags: make(cloudmodel.UUIDToCloudTags),
				}
			}
			cloudMD.SubDomainResources[podNamespace.SubDomain].PodNamespaceCloudTags[podNamespace.Lcuuid] = podNamespace.CloudTags
		}

		for _, lb := range toolDS.additionalLBs {
			lbUUID := common.GenerateUUID(lb.Name + lb.VPCUUID)
			modelLB := cloudmodel.LB{
				Lcuuid:       lbUUID,
				Name:         lb.Name,
				Model:        lb.Model,
				VPCLcuuid:    lb.VPCUUID,
				RegionLcuuid: lb.RegionUUID,
			}

			// add vinterface
			for _, vif := range lb.VInterfaces {
				vifUUID := common.GenerateUUID(vif.SubnetUUID + vif.Mac)
				cloudMD.VInterfaces = append(
					cloudMD.VInterfaces,
					cloudmodel.VInterface{
						Lcuuid:        vifUUID,
						Mac:           vif.Mac,
						Type:          toolDS.subnetUUIDToType[vif.SubnetUUID],
						DeviceType:    common.VIF_DEVICE_TYPE_LB,
						DeviceLcuuid:  lbUUID,
						NetworkLcuuid: vif.SubnetUUID,
						RegionLcuuid:  toolDS.regionUUID,
					},
				)
				for _, ip := range vif.IPs {
					var subnetCIDRUUID string
					for cidr, uuid := range toolDS.subnetToCIDRToCIDRUUID[vif.SubnetUUID] {
						if isIPInCIDR(cidr, ip) {
							subnetCIDRUUID = uuid
							break
						}
					}
					if subnetCIDRUUID == "" {
						return nil, servicecommon.NewError(
							httpcommon.RESOURCE_NOT_FOUND,
							fmt.Sprintf("lb (name: %s) vinterface (mac: %s) ip: %s is not in any cidr", lb.Name, vif.Mac, ip),
						)
					}
					cloudMD.IPs = append(
						cloudMD.IPs,
						cloudmodel.IP{
							Lcuuid:           common.GenerateUUID(vifUUID + ip),
							IP:               ip,
							VInterfaceLcuuid: vifUUID,
							SubnetLcuuid:     subnetCIDRUUID,
							RegionLcuuid:     toolDS.regionUUID,
						},
					)
				}
			}

			// add load balance if exists
			var vip string
			for i, lbListener := range lb.LBListeners {
				if i == 0 {
					vip = lbListener.IP
				} else {
					vip += "," + lbListener.IP
				}
				lbListenerUUID := common.GenerateUUID(lbUUID + lbListener.IP + strconv.Itoa(lbListener.Port))
				lbListenerName := lbListener.Name
				if lbListener.Name == "" {
					lbListenerName = fmt.Sprintf("%s-%d", lbListener.IP, lbListener.Port)
				}
				modelLBListener := cloudmodel.LBListener{
					Lcuuid:   lbListenerUUID,
					LBLcuuid: lbUUID,
					Name:     lbListenerName,
					IPs:      lbListener.IP,
					Port:     lbListener.Port,
					Protocol: lbListener.Protocol,
				}
				cloudMD.LBListeners = append(cloudMD.LBListeners, modelLBListener)

				// add load balance target server if exists
				for _, lbTargetServer := range lbListener.LBTargetServers {
					modelLBTargetServer := cloudmodel.LBTargetServer{
						Lcuuid:           common.GenerateUUID(lbListenerUUID + lbTargetServer.IP + strconv.Itoa(lbTargetServer.Port)),
						LBLcuuid:         lbUUID,
						LBListenerLcuuid: lbListenerUUID,
						Type:             controllercommon.LB_SERVER_TYPE_IP,
						IP:               lbTargetServer.IP,
						Port:             lbTargetServer.Port,
						Protocol:         lbListener.Protocol,
						VPCLcuuid:        lb.VPCUUID,
					}
					cloudMD.LBTargetServers = append(cloudMD.LBTargetServers, modelLBTargetServer)
				}
			}
			modelLB.VIP = vip
			cloudMD.LB = append(cloudMD.LB, modelLB)
		}

		domainUUIDToCloudModelData[domainUUID] = cloudMD
		log.Debugf("domain (uuid: %s) cloud data: %#v", cloudMD)
	}
	return domainUUIDToCloudModelData, nil
}

func getRegionDataFromDB(domainUUIDs []string) (map[string]string, error) {
	var dbItems []mysql.Domain
	err := mysql.Db.Where("lcuuid IN (?)", domainUUIDs).Find(&dbItems).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query domain failed: %s", err.Error()),
		)
	}
	domainUUIDToRegionUUID := make(map[string]string)
	for _, domain := range dbItems {
		conf := make(map[string]interface{})
		err := json.Unmarshal([]byte(domain.Config), &conf)
		if err != nil {
			return nil, servicecommon.NewError(
				httpcommon.SERVER_ERROR,
				fmt.Sprintf("get domain (uuid: %s) region info failed: %s", domain.Lcuuid, err.Error()),
			)
		}
		domainUUIDToRegionUUID[domain.Lcuuid] = conf["region_uuid"].(string)
	}
	return domainUUIDToRegionUUID, nil
}

func getAZDataFromDB(domainUUIDs []string) (map[string][]string, error) {
	var azs []mysql.AZ
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&azs).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query az failed: %s", err.Error()),
		)
	}
	domainUUIDToAZUUIDs := make(map[string][]string)
	for _, az := range azs {
		domainUUIDToAZUUIDs[az.Domain] = append(domainUUIDToAZUUIDs[az.Domain], az.Lcuuid)
	}
	return domainUUIDToAZUUIDs, nil
}

func getVPCDataFromDB(domainUUIDs []string) (map[string][]string, error) {
	var vpcs []mysql.VPC
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&vpcs).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query vpc failed: %s", err.Error()),
		)
	}
	domainUUIDToVPCUUIDs := make(map[string][]string)
	for _, vpc := range vpcs {
		domainUUIDToVPCUUIDs[vpc.Domain] = append(domainUUIDToVPCUUIDs[vpc.Domain], vpc.Lcuuid)
	}
	return domainUUIDToVPCUUIDs, nil
}

func getSubnetDataFromDB(domainUUIDs []string) (map[string]map[string]int, map[string]map[string]map[string]string, error) {
	var subnets []mysql.Network
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&subnets).Error
	if err != nil {
		return nil, nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query subnet failed: %s", err.Error()),
		)
	}
	domainUUIDToSubnetInfoMap := make(map[string]map[string]int)
	domainUUIDToSubnetCIDRInfoMap := make(map[string]map[string]map[string]string)
	for _, subnet := range subnets {
		_, ok := domainUUIDToSubnetInfoMap[subnet.Domain]
		if !ok {
			domainUUIDToSubnetInfoMap[subnet.Domain] = make(map[string]int)
			domainUUIDToSubnetCIDRInfoMap[subnet.Domain] = make(map[string]map[string]string)
		}
		domainUUIDToSubnetInfoMap[subnet.Domain][subnet.Lcuuid] = subnet.NetType

		subnetCIDRToUUID := make(map[string]string)
		var subnetCIDRs []mysql.Subnet
		err := mysql.Db.Where("vl2id = ?", subnet.ID).Find(&subnetCIDRs).Error
		if err != nil {
			return nil, nil, servicecommon.NewError(
				httpcommon.SERVER_ERROR,
				fmt.Sprintf("db query subnet_cidr failed: %s", err.Error()),
			)
		}
		for _, subnetCIDR := range subnetCIDRs {
			cidr := ipAndStrMaskToCIDR(subnetCIDR.Prefix, subnetCIDR.Netmask)
			if cidr == "" {
				return nil, nil, servicecommon.NewError(
					httpcommon.SERVER_ERROR,
					fmt.Sprintf("format db subnet_cidr (uuid: %s) failed", subnetCIDR.Lcuuid),
				)
			}
			subnetCIDRToUUID[cidr] = subnetCIDR.Lcuuid
		}
		domainUUIDToSubnetCIDRInfoMap[subnet.Domain][subnet.Lcuuid] = subnetCIDRToUUID
	}
	return domainUUIDToSubnetInfoMap, domainUUIDToSubnetCIDRInfoMap, nil
}

func getDataInfoFromDB(domainUUIDs []string) (map[string]map[string]string, error) {
	var hosts []mysql.Host
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&hosts).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query host failed: %s", err.Error()),
		)
	}
	domainUUIDToHostIPMap := make(map[string]map[string]string)
	for _, host := range hosts {
		_, ok := domainUUIDToHostIPMap[host.Domain]
		if !ok {
			domainUUIDToHostIPMap[host.Domain] = make(map[string]string)
		}
		domainUUIDToHostIPMap[host.Domain][host.IP] = host.Lcuuid
	}
	return domainUUIDToHostIPMap, nil
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

func ipAndStrMaskToCIDR(ip, mask string) string {
	maskIP := net.ParseIP(mask).To4()
	if maskIP == nil {
		maskIP = net.ParseIP(mask).To16()
	}
	if maskIP == nil {
		return ""
	}
	maskInt, _ := net.IPMask(maskIP).Size()
	return fmt.Sprintf("%s/%d", ip, maskInt)
}

func isIPInCIDR(cidr, ip string) bool {
	i := net.ParseIP(ip)
	_, c, _ := net.ParseCIDR(cidr)
	return c.Contains(i)
}

func getCHostsFromDB(domainUUIDs []string) (map[string]map[string]mysql.VM, error) {
	var chosts []mysql.VM
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&chosts).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.SERVER_ERROR,
			fmt.Sprintf("db query vm failed: %s", err.Error()),
		)
	}
	domainUUIDToCHostNameToInfo := make(map[string]map[string]mysql.VM)
	for _, chost := range chosts {
		if _, ok := domainUUIDToCHostNameToInfo[chost.Domain]; !ok {
			domainUUIDToCHostNameToInfo[chost.Domain] = make(map[string]mysql.VM)
		}
		domainUUIDToCHostNameToInfo[chost.Domain][chost.Name] = chost
	}
	return domainUUIDToCHostNameToInfo, nil
}

func getPodNamespaceFromDB(domainUUIDs []string) (map[string]map[string]mysql.PodNamespace, error) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Where("domain IN (?)", domainUUIDs).Find(&podNamespaces).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("db query pod_namespace failed: %s", err),
		)
	}
	domainUUIDToPodNSNameToInfo := make(map[string]map[string]mysql.PodNamespace)
	for _, podNamespace := range podNamespaces {
		if _, ok := domainUUIDToPodNSNameToInfo[podNamespace.Domain]; !ok {
			domainUUIDToPodNSNameToInfo[podNamespace.Domain] = make(map[string]mysql.PodNamespace)
		}
		domainUUIDToPodNSNameToInfo[podNamespace.Domain][podNamespace.Name] = podNamespace
	}
	return domainUUIDToPodNSNameToInfo, nil
}

func getPodNamespaceInSubdomainFromDB(domainUUIDs []string) (map[string]map[string]mysql.PodNamespace, error) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Where("domain IN (?) and sub_domain != ''", domainUUIDs).Find(&podNamespaces).Error
	if err != nil {
		return nil, servicecommon.NewError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("db query pod_namespace failed: %s", err),
		)
	}
	subdomainUUIDToPodNSNameToInfo := make(map[string]map[string]mysql.PodNamespace)
	for _, podNamespace := range podNamespaces {
		if _, ok := subdomainUUIDToPodNSNameToInfo[podNamespace.SubDomain]; !ok {
			subdomainUUIDToPodNSNameToInfo[podNamespace.SubDomain] = make(map[string]mysql.PodNamespace)
		}
		subdomainUUIDToPodNSNameToInfo[podNamespace.SubDomain][podNamespace.Name] = podNamespace
	}
	return subdomainUUIDToPodNSNameToInfo, nil
}

func convertTagsToMap(tags []model.AdditionalResourceTag) (map[string]string, error) {
	// If tag is not set then return null value as delete.
	ret := map[string]string{}
	if len(tags) == 0 {
		return ret, nil
	}

	for _, tag := range tags {
		if err := isTagValid(tag.Key, true); err != nil {
			return ret, err
		}
		if err := isTagValid(tag.Value, false); err != nil {
			return ret, err
		}
		ret[tag.Key] = tag.Value
	}
	return ret, nil
}

func isTagValid(str string, isKey bool) error {
	if str == "" {
		return errors.New("the key and value of tags do not support null values")
	}
	if strings.Contains(str, " ") {
		return fmt.Errorf("%s can not support spaces", str)
	}
	if strings.Contains(str, ":") {
		return fmt.Errorf("%s can not support colon", str)
	}
	if strings.Contains(str, "`") {
		return fmt.Errorf("%s can not support back quotes", str)
	}
	if strings.Contains(str, "\\") {
		return fmt.Errorf("%s can not support backslash", str)
	}

	if isKey {
		if strings.Contains(str, "'") {
			return fmt.Errorf("%s can not support single quotes", str)
		}
	}
	return nil
}
