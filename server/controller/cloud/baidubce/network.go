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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/vpc"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getNetworks(
	region model.Region, zoneNameToAZLcuuid map[string]string, vpcIdToLcuuid map[string]string,
) ([]model.Network, []model.Subnet, map[string]string, error) {
	var retNetworks []model.Network
	var retSubnets []model.Subnet
	var networkIdToLcuuid map[string]string

	log.Debug("get networks starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	vpcClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &vpc.ListSubnetArgs{}
	results := make([]*vpc.ListSubnetResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := vpcClient.ListSubnets(args)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListSubnets", len(result.Subnets), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListSubnets", " ", structToJson(results))
	networkIdToLcuuid = make(map[string]string)
	for _, r := range results {
		for _, subnet := range r.Subnets {
			azLcuuid, ok := zoneNameToAZLcuuid[subnet.ZoneName]
			if !ok {
				log.Infof("network (%s) az (%s) not found", subnet.SubnetId, subnet.ZoneName)
				continue
			}
			vpcLcuuid, ok := vpcIdToLcuuid[subnet.VPCId]
			if !ok {
				log.Infof("network (%s) vpc (%s) not found", subnet.SubnetId, subnet.VPCId)
				continue
			}

			networkLcuuid := common.GenerateUUID(subnet.SubnetId)
			retNetwork := model.Network{
				Lcuuid:       networkLcuuid,
				Name:         subnet.Name,
				VPCLcuuid:    vpcLcuuid,
				Shared:       false,
				External:     false,
				NetType:      common.NETWORK_TYPE_LAN,
				AZLcuuid:     azLcuuid,
				RegionLcuuid: region.Lcuuid,
			}
			retNetworks = append(retNetworks, retNetwork)
			networkIdToLcuuid[subnet.SubnetId] = networkLcuuid
			b.azLcuuidToResourceNum[retNetwork.AZLcuuid]++
			b.regionLcuuidToResourceNum[retNetwork.RegionLcuuid]++

			retSubnet := model.Subnet{
				Lcuuid:        common.GenerateUUID(networkLcuuid),
				Name:          subnet.Name,
				CIDR:          subnet.Cidr,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
			}
			retSubnets = append(retSubnets, retSubnet)
		}
	}
	log.Debug("Get networks complete")
	return retNetworks, retSubnets, networkIdToLcuuid, nil
}
