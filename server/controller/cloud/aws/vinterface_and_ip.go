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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
	"inet.af/netaddr"
)

func (a *Aws) getVInterfacesAndIPs(region awsRegion) ([]model.VInterface, []model.IP, []model.NATRule, error) {
	log.Debug("get vinterfaces,ips starting")
	a.publicIPToVinterface = map[string]model.VInterface{}
	var vinterfaces []model.VInterface
	var ips []model.IP
	var vNatRules []model.NATRule

	var retVinterfaces []types.NetworkInterface
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeNetworkInterfacesInput
		if nextToken == "" {
			input = &ec2.DescribeNetworkInterfacesInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeNetworkInterfacesInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := a.ec2Client.DescribeNetworkInterfaces(context.TODO(), input)
		if err != nil {
			log.Errorf("vinterface request aws api error: (%s)", err.Error())
			return []model.VInterface{}, []model.IP{}, []model.NATRule{}, err
		}
		retVinterfaces = append(retVinterfaces, result.NetworkInterfaces...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, vData := range retVinterfaces {
		mac := a.getStringPointerValue(vData.MacAddress)
		if vData.Attachment == nil {
			log.Debugf("vinterface (%s) not binding device", mac)
			continue
		}
		if vData.Attachment.InstanceId != nil {
			vinterfaceLcuuid := common.GetUUID(a.getStringPointerValue(vData.NetworkInterfaceId), uuid.Nil)
			deviceLcuuid := common.GetUUID(a.getStringPointerValue(vData.Attachment.InstanceId), uuid.Nil)
			networkLcuuid := common.GetUUID(a.getStringPointerValue(vData.SubnetId), uuid.Nil)
			vpcLcuuid := common.GetUUID(a.getStringPointerValue(vData.VpcId), uuid.Nil)
			vinterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           mac,
				DeviceLcuuid:  deviceLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.lcuuid),
			}
			vinterfaces = append(vinterfaces, vinterface)
			for _, ip := range vData.PrivateIpAddresses {
				privateIP := a.getStringPointerValue(ip.PrivateIpAddress)
				netPrivateIP, err := netaddr.ParseIP(privateIP)
				if err == nil && netPrivateIP.Is4() {
					ips = append(ips, model.IP{
						Lcuuid:           common.GetUUID(vinterfaceLcuuid+privateIP, uuid.Nil),
						VInterfaceLcuuid: vinterfaceLcuuid,
						IP:               privateIP,
						SubnetLcuuid:     common.GetUUID(networkLcuuid, uuid.Nil),
						RegionLcuuid:     a.getRegionLcuuid(region.lcuuid),
					})
				} else {
					log.Infof("ip (%s) not support", privateIP)
				}

				if vData.Association == nil {
					log.Debug("association is nil")
					continue
				}
				publicIP := a.getStringPointerValue(vData.Association.PublicIp)
				netPublicIP, err := netaddr.ParseIP(publicIP)
				if err == nil && netPublicIP.Is4() {
					vLcuuid := common.GetUUID(vinterfaceLcuuid, uuid.Nil)
					vinterfaces = append(vinterfaces, model.VInterface{
						Lcuuid:        vLcuuid,
						Type:          common.VIF_TYPE_WAN,
						Mac:           "ff" + mac[2:],
						DeviceLcuuid:  deviceLcuuid,
						DeviceType:    common.VIF_DEVICE_TYPE_VM,
						NetworkLcuuid: common.NETWORK_ISP_LCUUID,
						VPCLcuuid:     vpcLcuuid,
						RegionLcuuid:  a.getRegionLcuuid(region.lcuuid),
					})

					ips = append(ips, model.IP{
						Lcuuid:           common.GetUUID(vinterfaceLcuuid+publicIP, uuid.Nil),
						VInterfaceLcuuid: vLcuuid,
						IP:               publicIP,
						RegionLcuuid:     a.getRegionLcuuid(region.lcuuid),
					})

					a.publicIPToVinterface[publicIP] = vinterface

					vNatRules = append(vNatRules, model.NATRule{
						Lcuuid:           common.GetUUID(publicIP+vinterfaceLcuuid+privateIP, uuid.Nil),
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
