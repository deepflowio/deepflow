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

package tencent

import (
	"inet.af/netaddr"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getVInterfacesAndIPs(region tencentRegion) ([]model.VInterface, []model.IP, []model.NATRule, error) {
	log.Debug("get vinterfaces,ips starting")
	t.publicIPToVinterface = map[string]model.VInterface{}
	var vinterfaces []model.VInterface
	var ips []model.IP
	var vNatRules []model.NATRule

	vAttrs := []string{"NetworkInterfaceId", "MacAddress", "SubnetId", "VpcId", "Attachment"}
	iAttrs := []string{"PrivateIpAddress", "PublicIpAddress"}
	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeNetworkInterfaces", region.name, "NetworkInterfaceSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("vinterface request tencent api error: (%s)", err.Error())
		return []model.VInterface{}, []model.IP{}, []model.NATRule{}, err
	}
	for _, vData := range resp {
		if !t.checkRequiredAttributes(vData, vAttrs) {
			continue
		}

		mac := vData.Get("MacAddress").MustString()
		deviceID := vData.Get("Attachment").Get("InstanceId").MustString()
		if deviceID == "" {
			log.Infof("vinterface (%s) not binding device", mac)
			continue
		}

		vpcID := vData.Get("VpcId").MustString()
		subnetID := vData.Get("SubnetId").MustString()
		vinterfaceID := vData.Get("NetworkInterfaceId").MustString()
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, vpcID)
		subnetLcuuid := common.GetUUIDByOrgID(t.orgID, subnetID)
		vinterfaceLcuuid := common.GetUUIDByOrgID(t.orgID, vinterfaceID)
		deviceLcuuid := common.GetUUIDByOrgID(t.orgID, deviceID)
		vinterface := model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           mac,
			DeviceLcuuid:  deviceLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_VM,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: subnetLcuuid,
			RegionLcuuid:  t.getRegionLcuuid(region.lcuuid),
		}
		vinterfaces = append(vinterfaces, vinterface)

		privateIPs := vData.Get("PrivateIpAddressSet")
		for private := range privateIPs.MustArray() {
			privateIPData := privateIPs.GetIndex(private)
			if !t.checkRequiredAttributes(privateIPData, iAttrs) {
				continue
			}

			privateFlag := false
			privateIP := privateIPData.Get("PrivateIpAddress").MustString()
			netPrivateIP, err := netaddr.ParseIP(privateIP)
			if err == nil && netPrivateIP.Is4() {
				privateFlag = true
				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid+privateIP),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               privateIP,
					SubnetLcuuid:     common.GetUUIDByOrgID(t.orgID, subnetLcuuid),
					RegionLcuuid:     t.getRegionLcuuid(region.lcuuid),
				})
			} else {
				log.Infof("ip (%s) not support", privateIP)
			}

			publicIP := privateIPData.Get("PublicIpAddress").MustString()
			netPublicIP, err := netaddr.ParseIP(publicIP)
			if err == nil && netPublicIP.Is4() {
				vLcuuid := common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid)
				vinterfaces = append(vinterfaces, model.VInterface{
					Lcuuid:        vLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           "ff" + mac[2:],
					DeviceLcuuid:  deviceLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  t.getRegionLcuuid(region.lcuuid),
				})

				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUIDByOrgID(t.orgID, deviceLcuuid+publicIP),
					VInterfaceLcuuid: vLcuuid,
					IP:               publicIP,
					RegionLcuuid:     t.getRegionLcuuid(region.lcuuid),
				})

				t.publicIPToVinterface[publicIP] = vinterface

				if privateFlag {
					vNatRules = append(vNatRules, model.NATRule{
						Lcuuid:           common.GetUUIDByOrgID(t.orgID, publicIP+"_"+privateIP),
						Type:             "DNAT",
						Protocol:         "ALL",
						FloatingIP:       publicIP,
						FixedIP:          privateIP,
						VInterfaceLcuuid: vinterfaceLcuuid,
					})
				}
			}
		}
	}
	log.Debug("get vinterfaces,ips complete")
	return vinterfaces, ips, vNatRules, nil
}
