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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getVPCs(region string) ([]model.VPC, error) {
	log.Debug("get vpcs starting", logger.NewORGPrefix(t.orgID))
	var vpcs []model.VPC

	attrs := []string{"VpcId", "VpcName", "CidrBlock"}
	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeVpcs", region, "VpcSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("vpc request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.VPC{}, err
	}
	for _, vData := range resp {
		if !t.checkRequiredAttributes(vData, attrs) {
			continue
		}
		vpcID := vData.Get("VpcId").MustString()
		vpcs = append(vpcs, model.VPC{
			Lcuuid:       common.GetUUIDByOrgID(t.orgID, vpcID),
			Name:         vData.Get("VpcName").MustString(),
			CIDR:         vData.Get("CidrBlock").MustString(),
			Label:        vpcID,
			RegionLcuuid: t.regionLcuuid,
		})
	}
	log.Debug("get vpcs complete", logger.NewORGPrefix(t.orgID))
	return vpcs, nil
}
