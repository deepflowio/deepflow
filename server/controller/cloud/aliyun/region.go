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
	"github.com/deepflowio/deepflow/server/controller/common"
	"sort"
)

func (a *Aliyun) getRegions() ([]model.Region, error) {
	var retRegions []model.Region

	log.Debug("get regions starting")
	request := ecs.CreateDescribeRegionsRequest()
	response, err := a.getRegionResponse(a.regionName, request)
	if err != nil {
		log.Error(err)
		return retRegions, err
	}

	for _, r := range response {
		regions, _ := r.Get("Region").Array()
		for i := range regions {
			region := r.Get("Region").GetIndex(i)

			localName := region.Get("LocalName").MustString()
			// 当存在区域白名单时，如果当前区域不在白名单中，则跳过
			if len(a.includeRegions) > 0 {
				regionIndex := sort.SearchStrings(a.includeRegions, localName)
				if regionIndex == len(a.includeRegions) || a.includeRegions[regionIndex] != localName {
					log.Infof("region (%s) not in include_regions", localName)
					continue
				}
			}
			// 当存在区域黑名单是，如果当前区域在黑名单中，则跳过
			if len(a.excludeRegions) > 0 {
				regionIndex := sort.SearchStrings(a.excludeRegions, localName)
				if regionIndex < len(a.excludeRegions) && a.excludeRegions[regionIndex] == localName {
					log.Infof("region (%s) in exclude_regions", localName)
					continue
				}
			}

			retRegion := model.Region{
				Lcuuid: common.GenerateUUID(region.Get("RegionId").MustString()),
				Label:  region.Get("RegionId").MustString(),
				Name:   localName,
			}
			retRegions = append(retRegions, retRegion)
		}
	}

	log.Debug("get regions complete")
	return retRegions, nil
}
