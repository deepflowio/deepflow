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
	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aliyun) getRegions() ([]model.Region, error) {
	var retRegions []model.Region

	log.Debug("get regions starting", logger.NewORGPrefix(a.orgID))
	request := ecs.CreateDescribeRegionsRequest()
	response, err := a.getRegionResponse(a.regionName, request)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(a.orgID))
		return retRegions, err
	}

	for _, r := range response {
		regions, _ := r.Get("Region").Array()
		for i := range regions {
			region := r.Get("Region").GetIndex(i)

			localName := region.Get("LocalName").MustString()
			// 区域白名单，如果当前区域不在白名单中，则跳过
			if _, ok := a.includeRegions[localName]; !ok {
				log.Infof("region (%s) not in include_regions", localName, logger.NewORGPrefix(a.orgID))
				continue
			}

			retRegion := model.Region{
				Label: region.Get("RegionId").MustString(),
				Name:  localName,
			}
			retRegions = append(retRegions, retRegion)
		}
	}

	log.Debug("get regions complete", logger.NewORGPrefix(a.orgID))
	return retRegions, nil
}
