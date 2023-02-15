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

package huawei

import (
	"fmt"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getRegions() ([]model.Region, error) {
	jRegions, err := h.getRawData(fmt.Sprintf("https://iam.%s/v3/regions", h.config.URLDomain), h.toolDataSet.configProjectToken, "regions")
	if err != nil {
		log.Errorf("request failed: %v", err)
		return nil, err
	}
	includedRegionIDs := []string{}
	for p := range h.projectTokenMap {
		includedRegionIDs = append(includedRegionIDs, p.name)
	}

	var regions []model.Region
	for i := range jRegions {
		jr := jRegions[i]
		if !cloudcommon.CheckJsonAttributes(jr, []string{"id", "locales"}) {
			continue
		}
		id := jr.Get("id").MustString()
		if len(includedRegionIDs) > 0 && !common.Contains(includedRegionIDs, id) {
			log.Infof("exclude region: %s, not included", id)
			continue
		}

		region := model.Region{
			Lcuuid: common.GenerateUUID(id + "_" + h.lcuuidGenerate),
		}
		cn, ok := jr.Get("locales").CheckGet("zh-cn")
		if ok && cn.MustString() != "" {
			region.Name = cn.MustString()
		} else {
			region.Name = id
		}
		regions = append(regions, region)
		h.toolDataSet.projectNameToRegionLcuuid[id] = region.Lcuuid
	}
	return regions, nil
}

func (h *HuaWei) projectNameToRegionLcuuid(projectName string) string {
	if h.config.RegionLcuuid != "" {
		return h.config.RegionLcuuid
	}
	return h.toolDataSet.projectNameToRegionLcuuid[projectName]
}
