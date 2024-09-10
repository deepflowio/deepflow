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

package volcengine

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getVPCs(sess *session.Session) ([]model.VPC, error) {
	log.Debug("get vpcs starting", logger.NewORGPrefix(v.orgID))
	var vpcs []model.VPC

	var retVPCs []*vpc.VpcForDescribeVpcsOutput
	var nextToken *string
	var maxResults int64 = 100
	for {
		input := &vpc.DescribeVpcsInput{MaxResults: &maxResults, NextToken: nextToken}
		result, err := vpc.New(sess).DescribeVpcs(input)
		if err != nil {
			log.Errorf("request volcengine (vpc.DescribeVpcs) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.VPC{}, err
		}
		retVPCs = append(retVPCs, result.Vpcs...)
		if v.getStringPointerValue(result.NextToken) == "" {
			break
		}
		nextToken = result.NextToken
	}

	for _, vpc := range retVPCs {
		if vpc == nil {
			continue
		}
		vpcID := v.getStringPointerValue(vpc.VpcId)
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, vpcID)
		vpcs = append(vpcs, model.VPC{
			Lcuuid:       vpcLcuuid,
			Name:         v.getStringPointerValue(vpc.VpcName),
			CIDR:         v.getStringPointerValue(vpc.CidrBlock),
			Label:        vpcID,
			RegionLcuuid: v.regionLcuuid,
		})
	}
	log.Debug("get vpcs complete", logger.NewORGPrefix(v.orgID))
	return vpcs, nil
}
