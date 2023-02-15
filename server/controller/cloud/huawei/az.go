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

func (h *HuaWei) getAZs() ([]model.AZ, error) {
	var azs []model.AZ
	for project, token := range h.projectTokenMap {
		jAZs, err := h.getRawData(
			fmt.Sprintf("https://ecs.%s.%s/v2.1/%s/os-availability-zone", project.name, h.config.URLDomain, project.id), token.token, "availabilityZoneInfo",
		)
		if err != nil {
			log.Errorf("request failed: %v", err)
			return nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jAZs {
			ja := jAZs[i]
			zname := ja.Get("zoneName").MustString()
			if !cloudcommon.CheckJsonAttributes(ja, []string{"zoneName"}) {
				log.Infof("exclude az: %s, missing attr", zname)
				continue
			}
			lcuuid := common.GenerateUUID(zname + "_" + h.lcuuidGenerate)
			azs = append(
				azs,
				model.AZ{
					Lcuuid:       lcuuid,
					Name:         zname,
					RegionLcuuid: regionLcuuid,
				},
			)
			h.toolDataSet.azNameToAZLcuuid[zname] = lcuuid
		}
	}
	return azs, nil
}
