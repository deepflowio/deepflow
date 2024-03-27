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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getAZs(region tencentRegion) ([]model.AZ, error) {
	log.Debug("get azs starting")
	var azs []model.AZ

	attrs := []string{"Zone", "ZoneName"}
	resp, err := t.getResponse("cvm", "2017-03-12", "DescribeZones", region.name, "ZoneSet", false, map[string]interface{}{})
	if err != nil {
		log.Errorf("az request tencent api error: (%s)", err.Error())
		return []model.AZ{}, err
	}
	for _, aData := range resp {
		if !t.checkRequiredAttributes(aData, attrs) {
			continue
		}
		zone := aData.Get("Zone").MustString()
		name := aData.Get("ZoneName").MustString()
		lcuuid := common.GenerateUUID(t.uuidGenerate + "_" + zone)
		if _, ok := t.azLcuuidMap[lcuuid]; !ok {
			log.Debugf("az (%s) has no resource", name)
			continue
		}
		azs = append(azs, model.AZ{
			Lcuuid:       lcuuid,
			Label:        zone,
			Name:         name,
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})
	}
	log.Debug("get azs complete")
	return azs, nil
}
