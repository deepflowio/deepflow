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
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getRegions() ([]string, error) {
	log.Debug("get regions starting", logger.NewORGPrefix(t.orgID))
	var regions []string

	attrs := []string{"RegionState", "Region", "RegionName"}
	resp, err := t.getResponse("cvm", "2017-03-12", "DescribeRegions", "", "RegionSet", false, map[string]interface{}{})
	if err != nil {
		log.Errorf("region request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []string{}, err
	}
	for _, rData := range resp {
		if !t.checkRequiredAttributes(rData, attrs) {
			continue
		}
		name := rData.Get("RegionName").MustString()
		// 区域白名单，如果当前区域不在白名单中，则跳过
		if _, ok := t.includeRegions[name]; !ok {
			log.Infof("region (%s) not in include_regions", name, logger.NewORGPrefix(t.orgID))
			continue
		}
		if rData.Get("RegionState").MustString() != "AVAILABLE" {
			log.Debug("region request tencent api region state not is available", logger.NewORGPrefix(t.orgID))
			continue
		}

		regions = append(regions, rData.Get("Region").MustString())
	}
	log.Debug("get regions complete", logger.NewORGPrefix(t.orgID))
	return regions, nil
}
