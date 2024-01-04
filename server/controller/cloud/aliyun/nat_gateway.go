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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"strconv"
	"strings"

	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
)

func (a *Aliyun) getNatGateways(region model.Region) (
	[]model.NATGateway, []model.NATRule, []model.VInterface, []model.IP, error,
) {
	var retNATGateways []model.NATGateway
	var retNATRules []model.NATRule
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get nat_gateways starting")
	request := vpc.CreateDescribeNatGatewaysRequest()
	response, err := a.getNatGatewayResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retNATGateways, retNATRules, retVInterfaces, retIPs, err
	}

	for _, r := range response {
		for i := range r.Get("NatGateway").MustArray() {
			natGateway := r.Get("NatGateway").GetIndex(i)

			err := a.checkRequiredAttributes(natGateway, []string{"NatGatewayId", "Name", "VpcId"})
			if err != nil {
				log.Info(err)
				continue
			}

			natGatewayId := natGateway.Get("NatGatewayId").MustString()
			natGatewayName := natGateway.Get("Name").MustString()
			if natGatewayName == "" {
				natGatewayName = natGatewayId
			}
			vpcId := natGateway.Get("VpcId").MustString()
			floatingIPs := []string{}
			ipList := natGateway.Get("IpLists").Get("IpList")
			for j := range ipList.MustArray() {
				ip := ipList.GetIndex(j)
				floatingIP := ip.Get("IpAddress").MustString()
				if floatingIP != "" {
					floatingIPs = append(floatingIPs, floatingIP)
				}
			}

			natGatewayLcuuid := common.GenerateUUID(natGatewayId)
			vpcLcuuid := common.GenerateUUID(vpcId)
			retNATGateway := model.NATGateway{
				Lcuuid:       natGatewayLcuuid,
				Name:         natGatewayName,
				Label:        natGatewayId,
				FloatingIPs:  strings.Join(floatingIPs, `,`),
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retNATGateways = append(retNATGateways, retNATGateway)
			a.regionLcuuidToResourceNum[retNATGateway.RegionLcuuid]++

			// 接口
			vinterfaceLcuuid := common.GenerateUUID(natGatewayLcuuid)
			retVInterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_WAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  natGatewayLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
				NetworkLcuuid: common.NETWORK_ISP_LCUUID,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			// IP
			for _, ip := range floatingIPs {
				ipLcuuid := common.GenerateUUID(vinterfaceLcuuid + ip)
				retIP := model.IP{
					Lcuuid:           ipLcuuid,
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
				}
				retIPs = append(retIPs, retIP)
			}

			// DNAT规则
			dnatTableIds := natGateway.Get("ForwardTableIds").Get("ForwardTableId").MustStringArray()
			tmpRules, err := a.getDNATRules(region, natGatewayId, dnatTableIds)
			if err != nil {
				return []model.NATGateway{}, []model.NATRule{}, []model.VInterface{}, []model.IP{}, err
			}
			retNATRules = append(retNATRules, tmpRules...)

			// SNAT规则
			snatTableIds := natGateway.Get("SnatTableIds").Get("SnatTableId").MustStringArray()
			tmpRules, err = a.getSNATRules(region, natGatewayId, snatTableIds)
			if err != nil {
				return []model.NATGateway{}, []model.NATRule{}, []model.VInterface{}, []model.IP{}, err
			}
			retNATRules = append(retNATRules, tmpRules...)
		}
	}
	log.Debug("get nat_gateways complete")
	return retNATGateways, retNATRules, retVInterfaces, retIPs, nil
}

func (a *Aliyun) getSNATRules(region model.Region, natGatewayId string, snatTableIds []string) ([]model.NATRule, error) {
	var retNATRules []model.NATRule

	for _, snatTableId := range snatTableIds {
		request := vpc.CreateDescribeSnatTableEntriesRequest()
		request.SnatTableId = snatTableId
		response, err := a.getSNatRuleResponse(region.Label, request)
		if err != nil {
			log.Error(err)
			return []model.NATRule{}, err
		}
		for _, s := range response {
			for j := range s.Get("SnatTableEntry").MustArray() {
				snat := s.Get("SnatTableEntry").GetIndex(j)
				err := a.checkRequiredAttributes(
					snat, []string{"SnatEntryId", "SnatIp", "SourceCIDR"},
				)
				if err != nil {
					continue
				}
				snatId := snat.Get("SnatEntryId").MustString()
				retNATRule := model.NATRule{
					Lcuuid:           common.GenerateUUID(snatId),
					NATGatewayLcuuid: common.GenerateUUID(natGatewayId),
					Type:             "SNAT",
					Protocol:         "ALL",
					FloatingIP:       snat.Get("SnatIp").MustString(),
					FixedIP:          snat.Get("SourceCIDR").MustString(),
				}
				retNATRules = append(retNATRules, retNATRule)
			}
		}
	}
	return retNATRules, nil
}

func (a *Aliyun) getDNATRules(region model.Region, natGatewayId string, dnatTableIds []string) ([]model.NATRule, error) {
	var retNATRules []model.NATRule

	for _, dnatTableId := range dnatTableIds {
		request := vpc.CreateDescribeForwardTableEntriesRequest()
		request.ForwardTableId = dnatTableId
		response, err := a.getDNatRuleResponse(region.Label, request)
		if err != nil {
			log.Error(err)
			return []model.NATRule{}, err
		}
		for _, f := range response {
			for j := range f.Get("ForwardTableEntry").MustArray() {
				dnat := f.Get("ForwardTableEntry").GetIndex(j)
				err := a.checkRequiredAttributes(
					dnat, []string{
						"ForwardEntryId", "IpProtocol", "ExternalIp",
						"ExternalPort", "InternalIp", "InternalPort"},
				)
				if err != nil {
					continue
				}

				dnatId := dnat.Get("ForwardEntryId").MustString()
				ipProtocol := dnat.Get("IpProtocol").MustString()
				protocol := strings.ToUpper(ipProtocol)
				if protocol == "ANY" {
					protocol = "ALL"
				}
				floatingIPPortStr := dnat.Get("ExternalPort").MustString()
				floatingIPPort, err := strconv.Atoi(floatingIPPortStr)
				if err != nil {
					floatingIPPort = 0
				}
				fixedIPPortStr := dnat.Get("InternalPort").MustString()
				fixedIPPort, err := strconv.Atoi(fixedIPPortStr)
				if err != nil {
					fixedIPPort = 0
				}
				floatingIP := dnat.Get("ExternalIp").MustString()
				fixedIP := dnat.Get("InternalIp").MustString()

				key := dnatId
				if key == "" {
					key = floatingIP + dnatTableId + floatingIPPortStr + ipProtocol + fixedIP + fixedIPPortStr
				}
				retNATRule := model.NATRule{
					Lcuuid:           common.GenerateUUID(key),
					NATGatewayLcuuid: common.GenerateUUID(natGatewayId),
					Type:             "DNAT",
					Protocol:         protocol,
					FloatingIP:       floatingIP,
					FloatingIPPort:   floatingIPPort,
					FixedIP:          fixedIP,
					FixedIPPort:      fixedIPPort,
				}
				retNATRules = append(retNATRules, retNATRule)
			}
		}
	}
	return retNATRules, nil
}
