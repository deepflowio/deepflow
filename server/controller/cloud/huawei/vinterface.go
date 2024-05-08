/*
 * Copyright (c) 2024 Yunshan VMs
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
	"strings"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

const (
	DEVICE_OWNER_VM_PRE       = "compute"
	DEVICE_OWNER_VM           = "compute:nova"
	DEVICE_OWNER_ROUTER_GW    = "network:router_gateway"
	DEVICE_OWNER_ROUTER_IFACE = "network:router_interface"
	DEVICE_OWNER_FLOATING_IP  = "network:floatingip"
	DEVICE_OWNER_DHCP         = "network:dhcp"
	DEVICE_OWNER_NAT_GATEWAY  = "network:nat_gateway"
)

func (h *HuaWei) getVInterfaces() ([]model.DHCPPort, []model.VInterface, []model.IP, []model.FloatingIP, []model.NATRule, error) {
	var dhcpPorts []model.DHCPPort
	var vifs []model.VInterface
	var ips []model.IP
	var fIPs []model.FloatingIP
	var natRules []model.NATRule
	vifRequiredAttrs := []string{"id", "mac_address", "network_id", "device_id", "device_owner"}
	for project, token := range h.projectTokenMap {
		jPorts, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://vpc.%s.%s/v1/%s/ports", project.name, h.config.Domain, project.id), token.token, "ports", pageQueryMethodMarker,
		))
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jPorts {
			jPort := jPorts[i]
			mac := jPort.Get("mac_address").MustString()
			if !cloudcommon.CheckJsonAttributes(jPort, vifRequiredAttrs) {
				log.Infof("exclude vinterface: %s, missing attr", mac)
				continue
			}
			id := jPort.Get("id").MustString()
			network := h.toolDataSet.lcuuidToNetwork[jPort.Get("network_id").MustString()]
			if network.Lcuuid == "" {
				log.Infof("exclude vinterface: %s, missing network info", mac)
				continue
			}
			var deviceID string
			deviceID = jPort.Get("device_id").MustString()
			deviceOwner := jPort.Get("device_owner").MustString()

			h.formatVInterfaceRelatedToolDataSet(jPort, deviceID, deviceOwner, network.VPCLcuuid)

			if !common.Contains([]string{DEVICE_OWNER_DHCP, DEVICE_OWNER_ROUTER_GW, DEVICE_OWNER_VM, DEVICE_OWNER_ROUTER_IFACE}, deviceOwner) && !strings.HasPrefix(deviceOwner, DEVICE_OWNER_VM_PRE) {
				log.Infof("exclude vinterface: %s, %s", mac, deviceOwner)
				continue
			}
			var deviceType int
			if deviceOwner == DEVICE_OWNER_ROUTER_GW {
				deviceType = common.VIF_DEVICE_TYPE_VROUTER
			} else if deviceOwner == DEVICE_OWNER_DHCP {
				deviceType = common.VIF_DEVICE_TYPE_DHCP_PORT
				name := network.Name + "_DHCP"
				if len(name) > 256 {
					name = name[:256]
				}
				deviceID = id
				dhcpPort := model.DHCPPort{
					Lcuuid:       id,
					Name:         name,
					VPCLcuuid:    network.VPCLcuuid,
					AZLcuuid:     network.AZLcuuid,
					RegionLcuuid: regionLcuuid,
				}
				dhcpPorts = append(dhcpPorts, dhcpPort)
			} else if strings.HasPrefix(deviceOwner, DEVICE_OWNER_VM_PRE) {
				deviceType = common.VIF_DEVICE_TYPE_VM
			} else if deviceOwner == DEVICE_OWNER_ROUTER_IFACE {
				deviceType = common.VIF_DEVICE_TYPE_VROUTER
			}
			vif := model.VInterface{
				Lcuuid:        id,
				Mac:           mac,
				Type:          common.VIF_TYPE_LAN,
				DeviceType:    deviceType,
				DeviceLcuuid:  deviceID,
				RegionLcuuid:  regionLcuuid,
				NetworkLcuuid: network.Lcuuid,
				VPCLcuuid:     network.VPCLcuuid,
			}
			vifs = append(vifs, vif)

			lIPs, fIP, natRule := h.formatIPsAndNATRules(jPort, vif)
			ips = append(ips, lIPs...)
			if fIP.Lcuuid != "" {
				fIPs = append(fIPs, fIP)
			}
			if natRule.Lcuuid != "" {
				natRules = append(natRules, natRule)
			}
		}

		h.formatPublicIPs(project, token.token)
	}
	return dhcpPorts, vifs, ips, fIPs, natRules, nil
}

func (h *HuaWei) formatVInterfaceRelatedToolDataSet(jPort *simplejson.Json, deviceID, deviceOwner, vpcLcuuid string) {
	jIPs, ok := jPort.CheckGet("fixed_ips")
	if !ok {
		return
	}
	ipRequiredAttrs := []string{"ip_address"}
	for i := range jIPs.MustArray() {
		jIP := jIPs.GetIndex(i)
		if !cloudcommon.CheckJsonAttributes(jIP, ipRequiredAttrs) {
			continue
		}
		ipAddr := jIP.Get("ip_address").MustString()
		if deviceOwner == DEVICE_OWNER_NAT_GATEWAY {
			h.toolDataSet.keyToNATGatewayLcuuid[VPCIPKey{vpcLcuuid, ipAddr}] = deviceID
		}
		if strings.HasPrefix(deviceOwner, DEVICE_OWNER_VM_PRE) {
			h.toolDataSet.keyToVMLcuuid[SubnetIPKey{jIP.Get("subnet_id").MustString(), ipAddr}] = deviceID
		}
	}
}

func (h *HuaWei) formatIPsAndNATRules(jPort *simplejson.Json, vif model.VInterface) (ips []model.IP, fIP model.FloatingIP, natRule model.NATRule) {
	jIPs, ok := jPort.CheckGet("fixed_ips")
	if !ok {
		return
	}
	ipRequiredAttrs := []string{"ip_address"}
	floatingIP := h.toolDataSet.macToFloatingIP[vif.Mac]
	if floatingIP != "" && vif.DeviceType == common.VIF_DEVICE_TYPE_VM {
		fIP = model.FloatingIP{
			Lcuuid:        common.GenerateUUIDByOrgID(h.orgID, vif.Lcuuid+floatingIP),
			IP:            floatingIP,
			VMLcuuid:      vif.DeviceLcuuid,
			NetworkLcuuid: vif.NetworkLcuuid,
			VPCLcuuid:     vif.VPCLcuuid,
			RegionLcuuid:  vif.RegionLcuuid,
		}
	}
	for i := range jIPs.MustArray() {
		jIP := jIPs.GetIndex(i)
		if !cloudcommon.CheckJsonAttributes(jIP, ipRequiredAttrs) {
			continue
		}
		ipAddr := jIP.Get("ip_address").MustString()
		var subnetLcuuid string
		for _, subnet := range h.toolDataSet.networkLcuuidToSubnets[vif.NetworkLcuuid] {
			if cloudcommon.IsIPInCIDR(ipAddr, subnet.CIDR) {
				subnetLcuuid = subnet.Lcuuid
				break
			}
		}
		ips = append(
			ips,
			model.IP{
				Lcuuid:           common.GenerateUUIDByOrgID(h.orgID, vif.Lcuuid+ipAddr),
				VInterfaceLcuuid: vif.Lcuuid,
				IP:               ipAddr,
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     vif.RegionLcuuid,
			},
		)
		h.toolDataSet.vinterfaceLcuuidToIPs[vif.Lcuuid] = append(h.toolDataSet.vinterfaceLcuuidToIPs[vif.Lcuuid], ipAddr)
		if floatingIP != "" {
			if i == 0 {
				natRule = model.NATRule{
					Lcuuid:           common.GenerateUUIDByOrgID(h.orgID, floatingIP+"_"+ipAddr),
					Type:             cloudcommon.NAT_RULE_TYPE_DNAT,
					Protocol:         cloudcommon.PROTOCOL_ALL,
					FloatingIP:       floatingIP,
					FixedIP:          ipAddr,
					VInterfaceLcuuid: vif.Lcuuid,
				}
			} else {
				natRule.FixedIP = natRule.FixedIP + "," + ipAddr
				natRule.Lcuuid = common.GenerateUUIDByOrgID(h.orgID, floatingIP+"_"+natRule.FixedIP)
			}
		}
	}
	return
}

func (h *HuaWei) formatPublicIPs(project Project, token string) error {
	jIPs, err := h.getRawData(newRawDataGetContext(
		fmt.Sprintf("https://vpc.%s.%s/v1/%s/publicips", project.name, h.config.Domain, project.id), token, "publicips", pageQueryMethodMarker,
	))
	if err != nil {
		return err
	}

	requiredAttrs := []string{"port_id", "public_ip_address"}
	for i := range jIPs {
		jIP := jIPs[i]
		if !cloudcommon.CheckJsonAttributes(jIP, requiredAttrs) {
			log.Infof("exclude public ip, missing attr")
			continue
		}
		h.toolDataSet.vinterfaceLcuuidToPublicIP[jIP.Get("port_id").MustString()] = jIP.Get("public_ip_address").MustString()
	}
	return nil
}
