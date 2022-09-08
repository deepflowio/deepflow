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

package tencent

import (
	"hash/fnv"
	"inet.af/netaddr"
	"strconv"

	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
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
		return []model.VInterface{}, []model.IP{}, []model.NATRule{}, nil
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
		vpcLcuuid := common.GetUUID(vpcID, uuid.Nil)
		subnetLcuuid := common.GetUUID(subnetID, uuid.Nil)
		vinterfaceLcuuid := common.GetUUID(vinterfaceID, uuid.Nil)
		deviceLcuuid := common.GetUUID(deviceID, uuid.Nil)
		vinterface := model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           mac,
			DeviceLcuuid:  deviceLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_VM,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: subnetLcuuid,
			RegionLcuuid:  region.lcuuid,
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
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+privateIP, uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               privateIP,
					SubnetLcuuid:     common.GetUUID(subnetLcuuid, uuid.Nil),
					RegionLcuuid:     region.lcuuid,
				})
			} else {
				log.Infof("ip (%s) not support", privateIP)
			}

			publicIP := privateIPData.Get("PublicIpAddress").MustString()
			netPublicIP, err := netaddr.ParseIP(publicIP)
			if err == nil && netPublicIP.Is4() {
				mHash := fnv.New32a()
				mHash.Write([]byte(mac))
				vMac := strconv.Itoa(int(mHash.Sum32()))[1:3] + mac[2:]
				vLcuuid := common.GetUUID(vinterfaceLcuuid, uuid.Nil)
				vinterfaces = append(vinterfaces, model.VInterface{
					Lcuuid:        vLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           vMac,
					DeviceLcuuid:  deviceLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  region.lcuuid,
				})

				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+publicIP, uuid.Nil),
					VInterfaceLcuuid: vLcuuid,
					IP:               publicIP,
					SubnetLcuuid:     common.GetUUID(common.NETWORK_ISP_LCUUID, uuid.Nil),
					RegionLcuuid:     region.lcuuid,
				})

				t.publicIPToVinterface[publicIP] = vinterface

				if privateFlag {
					vNatRules = append(vNatRules, model.NATRule{
						Lcuuid:           common.GetUUID(publicIP+"_"+privateIP, uuid.Nil),
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
