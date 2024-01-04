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
	"sort"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (a *Aws) getRegions() ([]awsRegion, error) {
	log.Debug("get regions starting")
	var regions []awsRegion

	awsClientConfig, _ := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(a.apiDefaultRegion), config.WithHTTPClient(a.httpClient))
	result, err := ec2.NewFromConfig(awsClientConfig).DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
	if err != nil {
		log.Errorf("region request aws api error: (%s)", err.Error())
		return []awsRegion{}, err
	}
	for _, rData := range result.Regions {

		name := a.getStringPointerValue(rData.RegionName)
		// 当存在区域白名单时，如果当前区域不在白名单中，则跳过
		if len(a.includeRegions) > 0 {
			regionIndex := sort.SearchStrings(a.includeRegions, name)
			if regionIndex == len(a.includeRegions) || a.includeRegions[regionIndex] != name {
				log.Infof("region (%s) not in include_regions", name)
				continue
			}
		}
		// 当存在区域黑名单是，如果当前区域在黑名单中，则跳过
		if len(a.excludeRegions) > 0 {
			regionIndex := sort.SearchStrings(a.excludeRegions, name)
			if regionIndex < len(a.excludeRegions) && a.excludeRegions[regionIndex] == name {
				log.Infof("region (%s) in exclude_regions", name)
				continue
			}
		}
		lcuuid := common.GetUUID(name, uuid.Nil)
		regions = append(regions, awsRegion{
			name:   name,
			lcuuid: lcuuid,
		})
	}
	log.Debug("get regions complete")
	return regions, nil
}
