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
	uuid "github.com/satori/go.uuid"
)

func (a *Aws) getAZs(region awsRegion) ([]model.AZ, error) {
	log.Debug("get azs starting")
	var azs []model.AZ

	result, err := a.ec2Client.DescribeAvailabilityZones(context.TODO(), &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		log.Errorf("az request aws api error: (%s)", err.Error())
		return []model.AZ{}, err
	}
	for _, aData := range result.AvailabilityZones {
		zoneName := a.getStringPointerValue(aData.ZoneName)
		lcuuid := common.GetUUID(zoneName, uuid.Nil)
		if _, ok := a.azLcuuidMap[lcuuid]; !ok {
			log.Debugf("az (%s) has no resource", zoneName)
			continue
		}
		azs = append(azs, model.AZ{
			Lcuuid:       lcuuid,
			Label:        a.getStringPointerValue(aData.ZoneId),
			Name:         zoneName,
			RegionLcuuid: a.getRegionLcuuid(region.lcuuid),
		})
	}
	log.Debug("get azs complete")
	return azs, nil
}
