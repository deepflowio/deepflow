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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getAZs(client *ec2.Client) ([]model.AZ, error) {
	log.Debug("get azs starting", logger.NewORGPrefix(a.orgID))
	var azs []model.AZ

	result, err := client.DescribeAvailabilityZones(context.TODO(), &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		log.Errorf("az request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
		return []model.AZ{}, err
	}
	for _, aData := range result.AvailabilityZones {
		zoneName := a.getStringPointerValue(aData.ZoneName)
		lcuuid := common.GetUUIDByOrgID(a.orgID, zoneName)
		if _, ok := a.azLcuuidMap[lcuuid]; !ok {
			log.Debugf("az (%s) has no resource", zoneName, logger.NewORGPrefix(a.orgID))
			continue
		}
		azs = append(azs, model.AZ{
			Lcuuid:       lcuuid,
			Label:        a.getStringPointerValue(aData.ZoneId),
			Name:         zoneName,
			RegionLcuuid: a.regionLcuuid,
		})
	}
	log.Debug("get azs complete", logger.NewORGPrefix(a.orgID))
	return azs, nil
}
