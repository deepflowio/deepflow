/*
 * Copyright (c) 2023 Yunshan NATGateways
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

package huawei

import (
	"fmt"
	"strconv"
	"strings"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getNATGateways() (
	natGateways []model.NATGateway, natRules []model.NATRule, vifs []model.VInterface, ips []model.IP, err error,
) {
	requiredAttrs := []string{"id", "name", "router_id"}
	for project, token := range h.projectTokenMap {
		jNGs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://nat.%s.%s/v2/%s/nat_gateways", project.name, h.config.Domain, project.id), token.token, "nat_gateways", pageQueryMethodMarker,
		))
		if err != nil {
			return nil, nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jNGs {
			jNG := jNGs[i]
			id := jNG.Get("id").MustString()
			name := jNG.Get("name").MustString()
			if !cloudcommon.CheckJsonAttributes(jNG, requiredAttrs) {
				log.Infof("exclude nat_gateway: %s, missing attr", name)
				continue
			}
			routerID := jNG.Get("router_id").MustString()
			if routerID == "" {
				log.Infof("exclude nat_gateway: %s, missing vpc info", name)
				continue
			}
			natGateway := model.NATGateway{
				Lcuuid:       id,
				Name:         name,
				Label:        id, // TODO vm的label取自name，区别
				VPCLcuuid:    routerID,
				RegionLcuuid: regionLcuuid,
			}
			natGateways = append(natGateways, natGateway)
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++
		}

		dnatRules, err := h.formatDNATRules(project, token.token)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		natRules = append(natRules, dnatRules...)
		snatRules, err := h.formatSNATRules(project, token.token)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		natRules = append(natRules, snatRules...)
	}

	for i, ng := range natGateways {
		floatingIPs := h.toolDataSet.natGatewayLcuuidToFloatingIPs[ng.Lcuuid]
		if len(floatingIPs) != 0 {
			natGateways[i].FloatingIPs = strings.Join(floatingIPs, common.STRINGS_JOIN_COMMA)
			vifLcuuid := common.GenerateUUID(ng.Lcuuid)
			vifs = append(
				vifs,
				model.VInterface{
					Lcuuid:        vifLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  ng.Lcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     ng.VPCLcuuid,
					RegionLcuuid:  ng.RegionLcuuid,
				},
			)
			for _, fip := range floatingIPs {
				ips = append(
					ips,
					model.IP{
						Lcuuid:           common.GenerateUUID(vifLcuuid + fip),
						VInterfaceLcuuid: vifLcuuid,
						IP:               fip,
						RegionLcuuid:     ng.RegionLcuuid,
					},
				)
			}
		}
	}
	return
}

func (h *HuaWei) formatDNATRules(project Project, token string) (natRules []model.NATRule, err error) {
	jRules, err := h.getRawData(newRawDataGetContext(
		fmt.Sprintf("https://nat.%s.%s/v2/%s/dnat_rules", project.name, h.config.Domain, project.id), token, "dnat_rules", pageQueryMethodMarker,
	))
	if err != nil {
		return
	}

	requiredAttrs := []string{"id", "nat_gateway_id", "protocol", "floating_ip_address", "external_service_port", "port_id", "internal_service_port"}
	for i := range jRules {
		jRule := jRules[i]
		id := jRule.Get("id").MustString()
		if !cloudcommon.CheckJsonAttributes(jRule, requiredAttrs) {
			log.Infof("exclude nat_gateway: %s, missing attr", id)
			continue
		}
		natGatewayID := jRule.Get("nat_gateway_id").MustString()
		protocol := strings.ToUpper(jRule.Get("protocol").MustString())
		if protocol == "ANY" {
			protocol = cloudcommon.PROTOCOL_ALL
		}
		floatingIPPortStr := jRule.Get("external_service_port").MustString()
		floatingIPPort, err := strconv.Atoi(floatingIPPortStr)
		if err != nil {
			floatingIPPort = 0
		}
		fixedIPPortStr := jRule.Get("internal_service_port").MustString()
		fixedIPPort, err := strconv.Atoi(fixedIPPortStr)
		if err != nil {
			fixedIPPort = 0
		}
		floatingIP := jRule.Get("floating_ip_address").MustString()
		ipFlag := "."
		if !strings.Contains(floatingIP, ipFlag) {
			ipFlag = ":"
		}
		var fixedIP string
		for _, ip := range h.toolDataSet.vinterfaceLcuuidToIPs[jRule.Get("port_id").MustString()] {
			if strings.Contains(ip, ipFlag) {
				fixedIP = ip
				break
			}
		}

		natRules = append(
			natRules,
			model.NATRule{
				Lcuuid:           id,
				NATGatewayLcuuid: natGatewayID,
				Type:             cloudcommon.NAT_RULE_TYPE_DNAT,
				Protocol:         protocol,
				VInterfaceLcuuid: jRule.Get("port_id").MustString(),
				FloatingIP:       floatingIP,
				FloatingIPPort:   floatingIPPort,
				FixedIP:          fixedIP,
				FixedIPPort:      fixedIPPort,
			},
		)
		if !common.Contains(h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID], floatingIP) {
			h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID] = append(h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID], floatingIP)
		}
	}
	return
}

func (h *HuaWei) formatSNATRules(project Project, token string) (natRules []model.NATRule, err error) {
	jRules, err := h.getRawData(newRawDataGetContext(
		fmt.Sprintf("https://nat.%s.%s/v2/%s/snat_rules", project.name, h.config.Domain, project.id), token, "snat_rules", pageQueryMethodMarker,
	))
	if err != nil {
		return
	}

	requiredAttrs := []string{"id", "nat_gateway_id", "floating_ip_address"}
	for i := range jRules {
		jRule := jRules[i]
		id := jRule.Get("id").MustString()
		if !cloudcommon.CheckJsonAttributes(jRule, requiredAttrs) {
			log.Infof("exclude nat_gateway: %s, missing attr", id)
			continue
		}
		networkID, ok := jRule.CheckGet("network_id")
		if !ok {
			log.Infof("exclude nat_gateway: %s, missing network info", id)
			continue
		}
		fixedIP, ok := h.toolDataSet.networkLcuuidToCIDR[networkID.MustString()]
		if !ok {
			log.Infof("exclude nat_gateway: %s, missing fixed ip", id)
			continue
		}
		natGatewayID := jRule.Get("nat_gateway_id").MustString()
		floatingIP := jRule.Get("floating_ip_address").MustString()
		natRules = append(
			natRules,
			model.NATRule{
				Lcuuid:           id,
				NATGatewayLcuuid: natGatewayID,
				Type:             cloudcommon.NAT_RULE_TYPE_SNAT,
				Protocol:         cloudcommon.PROTOCOL_ALL,
				FloatingIP:       floatingIP,
				FixedIP:          fixedIP,
			},
		)
		if !common.Contains(h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID], floatingIP) {
			h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID] = append(h.toolDataSet.natGatewayLcuuidToFloatingIPs[natGatewayID], floatingIP)
		}
	}
	return
}
