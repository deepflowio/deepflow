/*
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

package resource

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func ListDomainAdditionalResource(resourceType, resourceName string) (map[string]interface{}, error) {
	resource, err := GetDomainAdditionalResource(resourceType, resourceName)
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	convertToUpperMap(data, reflect.ValueOf(resource).Elem())
	return data, nil
}

func GetDomainAdditionalResource(resourceType, resourceName string) (*model.AdditionalResource, error) {
	domainToResource, err := getResourceFromDB()
	if err != nil {
		return nil, err
	}

	resp := &model.AdditionalResource{}
	for domain, resource := range domainToResource {
		switch resourceType {
		case "az":
			resp.AZs = append(resp.AZs, getAZs(resource.AZs, domain, resourceName)...)
		case "vpc":
			resp.VPCs = append(resp.VPCs, getVPCs(resource.VPCs, domain, resourceName)...)
		case "subnet":
			resp.Subnets = append(resp.Subnets, getSubnets(resource.Subnets, resource.SubnetCIDRs, domain, resourceName)...)
		case "host":
			resp.Hosts = append(resp.Hosts, getHosts(resource.Hosts, resource.VInterfaces, resource.IPs, domain, resourceName)...)
		case "chost":
			resp.CHosts = append(resp.CHosts, getCHosts(resource.CHosts, resource.VInterfaces, resource.IPs, domain, resourceName)...)
		case "lb":
			resp.LB = append(resp.LB, getLBs(resource.LB, resource.LBListeners, resource.LBTargetServers,
				resource.VInterfaces, resource.IPs, domain, resourceName)...)
		case "cloud-tag":
			cloudTags, err := getClouTags(resource, domain, resourceName)
			if err != nil {
				return nil, err
			}
			resp.CloudTags = append(resp.CloudTags, cloudTags...)
		case "":
			resp.AZs = append(resp.AZs, getAZs(resource.AZs, domain, resourceName)...)
			resp.VPCs = append(resp.VPCs, getVPCs(resource.VPCs, domain, resourceName)...)
			resp.Subnets = append(resp.Subnets, getSubnets(resource.Subnets, resource.SubnetCIDRs, domain, resourceName)...)
			resp.Hosts = append(resp.Hosts, getHosts(resource.Hosts, resource.VInterfaces, resource.IPs, domain, resourceName)...)
			resp.CHosts = append(resp.CHosts, getCHosts(resource.CHosts, resource.VInterfaces, resource.IPs, domain, resourceName)...)
			resp.LB = append(resp.LB, getLBs(resource.LB, resource.LBListeners, resource.LBTargetServers,
				resource.VInterfaces, resource.IPs, domain, resourceName)...)
			cloudTags, err := getClouTags(resource, domain, resourceName)
			if err != nil {
				return nil, err
			}
			resp.CloudTags = append(resp.CloudTags, cloudTags...)

		default:
			return nil, fmt.Errorf("resource type(%v) is not supported, please enter: az, vpc, subnet, host, chost, lb, cloud-tag")
		}
	}

	return resp, nil
}

func getAZs(azs []cloudmodel.AZ, domain, resourceName string) []model.AdditionalResourceAZ {
	var resp []model.AdditionalResourceAZ
	for _, az := range azs {
		if resourceName != "" && az.Name != resourceName {
			continue
		}
		resp = append(resp, model.AdditionalResourceAZ{
			Name:       az.Name,
			UUID:       az.Lcuuid,
			DomainUUID: domain,
		})
	}
	return resp
}

func getVPCs(vpcs []cloudmodel.VPC, domain, resourceName string) []model.AdditionalResourceVPC {
	var resp []model.AdditionalResourceVPC
	for _, vpc := range vpcs {
		if resourceName != "" && vpc.Name != resourceName {
			continue
		}
		resp = append(resp, model.AdditionalResourceVPC{
			Name:       vpc.Name,
			UUID:       vpc.Lcuuid,
			DomainUUID: domain,
		})
	}
	return resp
}

func getSubnets(subnets []cloudmodel.Network, subnetCIDRs []cloudmodel.Subnet, domain, resourceName string) []model.AdditionalResourceSubnet {
	var resp []model.AdditionalResourceSubnet
	for _, subnet := range subnets {
		if resourceName != "" && subnet.Name != resourceName {
			continue
		}
		subnetAdd := model.AdditionalResourceSubnet{
			DomainUUID: domain,
			UUID:       subnet.Lcuuid,
			Name:       subnet.Name,
			Type:       subnet.NetType,
			VPCUUID:    subnet.VPCLcuuid,
			AZUUID:     subnet.AZLcuuid,
			IsVIP:      subnet.IsVIP,
		}
		for _, subnetCIDR := range subnetCIDRs {
			if subnetCIDR.NetworkLcuuid != subnet.Lcuuid &&
				subnetCIDR.Lcuuid != common.GenerateUUID(subnet.Lcuuid+subnetCIDR.CIDR) {
				continue
			}
			subnetAdd.CIDRs = append(subnetAdd.CIDRs, subnetCIDR.CIDR)
		}
		resp = append(resp, subnetAdd)
	}
	return resp
}

func getHosts(hosts []cloudmodel.Host, vifs []cloudmodel.VInterface, ips []cloudmodel.IP, domain, resourceName string) []model.AdditionalResourceHost {
	var resp []model.AdditionalResourceHost
	for _, host := range hosts {
		if resourceName != "" && host.Name != resourceName {
			continue
		}
		addHost := model.AdditionalResourceHost{
			DomainUUID: domain,
			AZUUID:     host.AZLcuuid,
			Name:       host.Name,
			UUID:       host.Lcuuid,
			IP:         host.IP,
			Type:       host.HType,
		}
		addHost.VInterfaces = append(addHost.VInterfaces, getVinterfaces(host.Lcuuid, vifs, ips)...)
		resp = append(resp, addHost)
	}
	return resp
}

func getCHosts(chosts []cloudmodel.VM, vifs []cloudmodel.VInterface, ips []cloudmodel.IP, domain, resourceName string) []model.AdditionalResourceChost {
	var resp []model.AdditionalResourceChost
	for _, chost := range chosts {
		if resourceName != "" && chost.Name != resourceName {
			continue
		}
		addCHost := model.AdditionalResourceChost{
			Name:       chost.Name,
			UUID:       chost.Lcuuid,
			HostIP:     chost.LaunchServer,
			Type:       chost.HType,
			VPCUUID:    chost.VPCLcuuid,
			DomainUUID: domain,
			AZUUID:     chost.AZLcuuid,
		}
		addCHost.VInterfaces = append(addCHost.VInterfaces, getVinterfaces(chost.Lcuuid, vifs, ips)...)
		resp = append(resp, addCHost)
	}
	return resp
}

func getLBs(lbs []cloudmodel.LB, lbListeners []cloudmodel.LBListener, lbTargetServers []cloudmodel.LBTargetServer,
	vifs []cloudmodel.VInterface, ips []cloudmodel.IP, domain, resourceName string) []model.AdditionalResourceLB {
	var resp []model.AdditionalResourceLB
	for _, lb := range lbs {
		if resourceName != "" && lb.Name != resourceName {
			continue
		}
		lbAdd := model.AdditionalResourceLB{
			Name:       lb.Name,
			Model:      lb.Model,
			VPCUUID:    lb.VPCLcuuid,
			DomainUUID: domain,
			RegionUUID: lb.RegionLcuuid,
		}
		lbAdd.VInterfaces = append(lbAdd.VInterfaces, getVinterfaces(lb.Lcuuid, vifs, ips)...)
		for _, lbListener := range lbListeners {
			if lbListener.LBLcuuid != lb.Lcuuid {
				continue
			}
			lbListenerAdd := model.AdditionalResourceLBListener{
				Name:     lbListener.Name,
				Protocol: lbListener.Protocol,
				IP:       lbListener.IPs,
				Port:     lbListener.Port,
			}
			for _, lbTargetServer := range lbTargetServers {
				if lbTargetServer.LBLcuuid != lb.Lcuuid && lbTargetServer.LBListenerLcuuid != lbListener.Lcuuid {
					continue
				}
				lbTargetServerAdd := model.AdditionalResourceLBTargetServer{
					IP:   lbTargetServer.IP,
					Port: lbTargetServer.Port,
				}
				lbListenerAdd.LBTargetServers = append(lbListenerAdd.LBTargetServers, lbTargetServerAdd)
			}
			lbAdd.LBListeners = append(lbAdd.LBListeners, lbListenerAdd)
		}

		resp = append(resp, lbAdd)
	}
	return resp
}

func convertToUpperMap(data map[string]interface{}, v reflect.Value) {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		tag := field.Tag.Get("json")
		if value.IsZero() && strings.Contains(tag, "omitempty") {
			continue
		}
		tag = strings.Split(tag, ",")[0]
		tag = strings.ToUpper(tag)

		switch value.Kind() {
		case reflect.Struct:
			subData := make(map[string]interface{})
			convertToUpperMap(subData, value)
			data[tag] = subData
		case reflect.Slice:
			sliceData := make([]interface{}, value.Len())
			for j := 0; j < value.Len(); j++ {
				subValue := value.Index(j)
				if subValue.Kind() == reflect.Struct {
					subData := make(map[string]interface{})
					convertToUpperMap(subData, subValue)
					sliceData[j] = subData
				} else {
					sliceData[j] = subValue.Interface()
				}
			}
			data[tag] = sliceData
		default:
			data[tag] = value.Interface()
		}
	}
}

func getResourceFromDB() (map[string]*cloudmodel.AdditionalResource, error) {
	var items []mysql.DomainAdditionalResource
	mysql.Db.Select("domain", "content").Where("content!=''").Find(&items)
	if len(items) == 0 {
		mysql.Db.Select("domain", "compressed_content").Find(&items)
		if len(items) == 0 {
			return nil, gorm.ErrRecordNotFound
		}
	}

	domainToResource := make(map[string]*cloudmodel.AdditionalResource, len(items))
	for _, item := range items {
		content := item.CompressedContent
		if len(item.CompressedContent) == 0 {
			content = []byte(item.Content)
		}
		additionalResource := &cloudmodel.AdditionalResource{}
		if err := json.Unmarshal(content, &additionalResource); err != nil {
			log.Errorf("domain (lcuuid: %s) json unmarshal content failed: %s", item.Domain, err.Error())
			continue
		}
		domainToResource[item.Domain] = additionalResource
	}

	return domainToResource, nil
}

func getVinterfaces(deviceUUID string, vifs []cloudmodel.VInterface, ips []cloudmodel.IP) []model.AdditionalResourceVInterface {
	var resp []model.AdditionalResourceVInterface
	for _, vif := range vifs {
		if vif.DeviceLcuuid != deviceUUID {
			continue
		}
		addVIF := model.AdditionalResourceVInterface{
			Mac:        vif.Mac,
			Name:       vif.Name,
			SubnetUUID: vif.NetworkLcuuid,
		}
		for _, ip := range ips {
			if ip.VInterfaceLcuuid != vif.Lcuuid &&
				ip.Lcuuid != common.GenerateUUID(vif.Lcuuid+ip.IP) {
				continue
			}
			addVIF.IPs = append(addVIF.IPs, ip.IP)
		}
		resp = append(resp, addVIF)
	}
	return resp
}

func getClouTags(resource *cloudmodel.AdditionalResource, domain, resourceName string) ([]model.AdditionalResourceCloudTag, error) {
	chostUUIDToName := make(map[string]string)
	podNSUUIDToName := make(map[string]string)
	podNSUUIDToSubdomain := make(map[string]string)

	var vms []mysql.VM
	if err := mysql.Db.Find(&vms).Error; err != nil {
		return nil, err
	}
	for _, vm := range vms {
		chostUUIDToName[vm.Lcuuid] = vm.Name
	}
	var podNamespaces []mysql.PodNamespace
	if err := mysql.Db.Find(&podNamespaces).Error; err != nil {
		return nil, err
	}
	for _, podNS := range podNamespaces {
		podNSUUIDToName[podNS.Lcuuid] = podNS.Name
		if podNS.SubDomain != "" {
			podNSUUIDToSubdomain[podNS.Lcuuid] = podNS.SubDomain
		}
	}

	var resp []model.AdditionalResourceCloudTag
	for uuid, cloudTags := range resource.CHostCloudTags {
		if resourceName != "" && chostUUIDToName[uuid] != resourceName {
			continue
		}
		addCHost := model.AdditionalResourceCloudTag{
			ResourceType: "chost",
			ResourceName: chostUUIDToName[uuid],
			DomainUUID:   domain,
		}
		for k, v := range cloudTags {
			addCHost.Tags = append(addCHost.Tags, model.AdditionalResourceTag{Key: k, Value: v})
		}
		resp = append(resp, addCHost)
	}

	genCloudTags := func(cloudTags cloudmodel.UUIDToCloudTags) []model.AdditionalResourceCloudTag {
		var ct []model.AdditionalResourceCloudTag
		for uuid, cloudTags := range cloudTags {
			if resourceName != "" && podNSUUIDToName[uuid] != resourceName {
				continue
			}
			addPodNS := model.AdditionalResourceCloudTag{
				ResourceType: "pod_ns",
				ResourceName: podNSUUIDToName[uuid],
				DomainUUID:   domain,
			}
			if subdomain, ok := podNSUUIDToSubdomain[uuid]; ok {
				addPodNS.SubDomainUUID = subdomain
			}
			for k, v := range cloudTags {
				addPodNS.Tags = append(addPodNS.Tags, model.AdditionalResourceTag{Key: k, Value: v})
			}
			ct = append(ct, addPodNS)
		}
		return ct
	}
	resp = append(resp, genCloudTags(resource.PodNamespaceCloudTags)...)
	for _, additionalResource := range resource.SubDomainResources {
		resp = append(resp, genCloudTags(additionalResource.PodNamespaceCloudTags)...)
	}
	return resp, nil
}
