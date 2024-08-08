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
	"sort"

	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getRegions() ([]string, error) {
	log.Debug("get regions starting", logger.NewORGPrefix(v.orgID))
	var regionIDs []string

	config := volcengine.NewConfig().
		WithCredentials(credentials.NewStaticCredentials(v.secretID, v.secretKey, "")).
		WithRegion(DEFAULT_REGION).
		WithHTTPClient(v.httpClient)

	sess, err := session.NewSession(config)
	if err != nil {
		log.Errorf("get volcengine session error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
		return []string{}, err
	}
	resp, err := ecs.New(sess).DescribeRegions(&ecs.DescribeRegionsInput{})
	if err != nil {
		log.Errorf("request volcengine (ecs.DescribeRegions) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
		return []string{}, err
	}
	for _, region := range resp.Regions {
		if region == nil {
			continue
		}
		regionID := v.getStringPointerValue(region.RegionId)
		// 当存在区域白名单时，如果当前区域不在白名单中，则跳过
		if len(v.includeRegions) > 0 {
			regionIndex := sort.SearchStrings(v.includeRegions, regionID)
			if regionIndex == len(v.includeRegions) || v.includeRegions[regionIndex] != regionID {
				log.Infof("region (%s) not in include_regions", regionID, logger.NewORGPrefix(v.orgID))
				continue
			}
		}
		// 当存在区域黑名单是，如果当前区域在黑名单中，则跳过
		if len(v.excludeRegions) > 0 {
			regionIndex := sort.SearchStrings(v.excludeRegions, regionID)
			if regionIndex < len(v.excludeRegions) && v.excludeRegions[regionIndex] == regionID {
				log.Infof("region (%s) in exclude_regions", regionID, logger.NewORGPrefix(v.orgID))
				continue
			}
		}
		regionIDs = append(regionIDs, regionID)
	}
	log.Debug("get regions complete", logger.NewORGPrefix(v.orgID))
	return regionIDs, nil
}
