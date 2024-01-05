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
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getVPCs(region model.Region) ([]model.VPC, error) {
	var retVPCs []model.VPC

	log.Debug("get vpcs starting")
	request := vpc.CreateDescribeVpcsRequest()
	response, err := a.getVpcResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retVPCs, err
	}

	for _, r := range response {
		vpcs, _ := r.Get("Vpc").Array()
		for i := range vpcs {
			vpc := r.Get("Vpc").GetIndex(i)

			vpcId := vpc.Get("VpcId").MustString()
			vpcName := vpc.Get("VpcName").MustString()
			cidr := vpc.Get("CidrBlock").MustString()
			if vpcName == "" {
				if cidr != "" {
					vpcName = cidr
				} else {
					vpcName = vpcId
				}
			}

			vpcLcuuid := common.GenerateUUID(vpcId)
			retVPC := model.VPC{
				Lcuuid:       vpcLcuuid,
				Name:         vpcName,
				Label:        vpcId,
				CIDR:         cidr,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retVPCs = append(retVPCs, retVPC)
			a.regionLcuuidToResourceNum[retVPC.RegionLcuuid]++
			a.vpcIDToLcuuids[vpcId] = vpcLcuuid
		}
	}
	log.Debug("get vpcs complete")
	return retVPCs, nil
}
