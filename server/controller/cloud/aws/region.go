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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getRegions() ([]string, error) {
	log.Debug("get regions starting", logger.NewORGPrefix(a.orgID))
	var regions []string

	if len(a.includeRegions) == 1 {
		for regionName := range a.includeRegions {
			regions = append(regions, regionName)
		}
		log.Debug("get regions complete", logger.NewORGPrefix(a.orgID))
		return regions, nil
	}

	awsClientConfig, _ := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(a.apiDefaultRegion), config.WithHTTPClient(a.httpClient))
	result, err := ec2.NewFromConfig(awsClientConfig).DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
	if err != nil {
		log.Errorf("region request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
		return []string{}, err
	}
	for _, rData := range result.Regions {
		name := a.getStringPointerValue(rData.RegionName)
		// 区域白名单，如果当前区域不在白名单中，则跳过
		if _, ok := a.includeRegions[name]; !ok {
			log.Infof("region (%s) not in include_regions", name, logger.NewORGPrefix(a.orgID))
			continue
		}
		regions = append(regions, name)
	}
	log.Debug("get regions complete", logger.NewORGPrefix(a.orgID))
	return regions, nil
}
