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

package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getNetworks(region model.Region) ([]model.Network, []model.Subnet, error) {
	var retNetworks []model.Network
	var retSubnets []model.Subnet

	log.Debug("get networks starting")
	request := vpc.CreateDescribeVSwitchesRequest()
	response, err := a.getNetworkResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retNetworks, retSubnets, err
	}
	for _, r := range response {
		networks, _ := r.Get("VSwitch").Array()
		for i := range networks {
			network := r.Get("VSwitch").GetIndex(i)

			err := a.checkRequiredAttributes(
				network,
				[]string{"VSwitchId", "VSwitchName", "VpcId", "ZoneId", "CidrBlock"},
			)
			if err != nil {
				continue
			}
			networkId := network.Get("VSwitchId").MustString()
			networkName := network.Get("VSwitchName").MustString()
			if networkName == "" {
				networkName = networkId
			}
			vpcId := network.Get("VpcId").MustString()
			azId := network.Get("ZoneId").MustString()
			cidr := network.Get("CidrBlock").MustString()

			networkLcuuid := common.GenerateUUID(networkId)
			vpcLcuuid := common.GenerateUUID(vpcId)
			retNetwork := model.Network{
				Lcuuid:         networkLcuuid,
				Name:           networkName,
				SegmentationID: 1,
				VPCLcuuid:      vpcLcuuid,
				Shared:         false,
				External:       false,
				NetType:        common.NETWORK_TYPE_LAN,
				AZLcuuid:       common.GenerateUUID(a.uuidGenerate + "_" + azId),
				RegionLcuuid:   a.getRegionLcuuid(region.Lcuuid),
			}
			retNetworks = append(retNetworks, retNetwork)
			a.azLcuuidToResourceNum[retNetwork.AZLcuuid]++
			a.regionLcuuidToResourceNum[retNetwork.RegionLcuuid]++

			retSubnet := model.Subnet{
				Lcuuid:        common.GenerateUUID(networkLcuuid),
				Name:          networkName,
				CIDR:          cidr,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
			}
			retSubnets = append(retSubnets, retSubnet)
		}
	}
	log.Debug("get networks complete")
	return retNetworks, retSubnets, nil
}
