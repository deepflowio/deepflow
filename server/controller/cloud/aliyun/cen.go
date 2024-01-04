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
	cbn "github.com/aliyun/alibaba-cloud-sdk-go/services/cbn"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getCens(region model.Region) ([]model.CEN, error) {
	var retCens []model.CEN

	log.Debug("get cens starting")
	request := cbn.CreateDescribeCensRequest()
	response, err := a.getCenResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	for _, r := range response {
		cens, _ := r.Get("Cen").Array()
		for i := range cens {
			cen := r.Get("Cen").GetIndex(i)

			cenId := cen.Get("CenId").MustString()
			if cenId == "" {
				continue
			}
			cenName := cen.Get("Name").MustString()
			if cenName == "" {
				cenName = cenId
			}

			childRequest := cbn.CreateDescribeCenAttachedChildInstancesRequest()
			childRequest.CenId = cenId
			childResponse, err := a.getCenAttributeResponse(region.Label, childRequest)
			if err != nil {
				log.Error(err)
				return nil, err
			}

			vpcLcuuids := []string{}
			for _, c := range childResponse {
				cenAttrs, _ := c.Get("ChildInstance").Array()
				for j := range cenAttrs {
					cenAttr := c.Get("ChildInstance").GetIndex(j)
					if cenAttr.Get("ChildInstanceType").MustString() != "VPC" {
						continue
					}
					vpcLcuuids = append(
						vpcLcuuids,
						common.GenerateUUID(cenAttr.Get("ChildInstanceId").MustString()),
					)
				}
			}
			if len(vpcLcuuids) == 0 {
				continue
			}
			retCens = append(retCens, model.CEN{
				Lcuuid:     common.GenerateUUID(cenId),
				Name:       cenName,
				Label:      cenId,
				VPCLcuuids: vpcLcuuids,
			})
		}
	}

	log.Debug("get cens complete")
	return retCens, nil
}
