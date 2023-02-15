/*
 * Copyright (c) 2022 Yunshan Networks
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
	"sort"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
)

func (t *Tencent) getRegions() ([]tencentRegion, error) {
	log.Debug("get regions starting")
	var regionList []tencentRegion

	attrs := []string{"RegionState", "Region", "RegionName"}
	resp, err := t.getResponse("cvm", "2017-03-12", "DescribeRegions", "", "RegionSet", false, map[string]interface{}{})
	if err != nil {
		log.Errorf("region request tencent api error: (%s)", err.Error())
		return []tencentRegion{}, err
	}
	for _, rData := range resp {
		if !t.checkRequiredAttributes(rData, attrs) {
			continue
		}
		name := rData.Get("RegionName").MustString()
		// 当存在区域白名单时，如果当前区域不在白名单中，则跳过
		if len(t.includeRegions) > 0 {
			regionIndex := sort.SearchStrings(t.includeRegions, name)
			if regionIndex == len(t.includeRegions) || t.includeRegions[regionIndex] != name {
				log.Infof("region (%s) not in include_regions", name)
				continue
			}
		}
		// 当存在区域黑名单是，如果当前区域在黑名单中，则跳过
		if len(t.excludeRegions) > 0 {
			regionIndex := sort.SearchStrings(t.excludeRegions, name)
			if regionIndex < len(t.excludeRegions) && t.excludeRegions[regionIndex] == name {
				log.Infof("region (%s) in exclude_regions", name)
				continue
			}
		}
		if rData.Get("RegionState").MustString() != "AVAILABLE" {
			log.Debug("region request tencent api region state not is available")
			continue
		}
		rRegion := rData.Get("Region").MustString()
		regionLcuuid := common.GetUUID(rRegion, uuid.Nil)
		finance := false
		if strings.Contains(name, FINANCE_REGION_PROFILE) {
			finance = true
		}
		regionList = append(regionList, tencentRegion{
			lcuuid:     regionLcuuid,
			name:       rRegion,
			regionName: name,
			finance:    finance,
		})
	}
	log.Debug("get regions complete")
	return regionList, nil
}
