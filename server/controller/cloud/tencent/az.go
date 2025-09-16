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
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getAZs(region string) ([]model.AZ, error) {
	log.Debug("get azs starting", logger.NewORGPrefix(t.orgID))
	var azs []model.AZ

	// 由于 cvm.DescribeZones 不再返回已售罄的 az，导致部分资源无法关联
	// 尝试使用 cdb.DescribeZones 接口获取所有 az
	attrs := []string{"Zone", "ZoneName"}
	params := map[string]interface{}{
		"Product": "cdb",
	}
	resp, err := t.getResponse("region", "2022-06-27", "DescribeZones", region, "ZoneSet", false, params)
	if err != nil {
		log.Errorf("az request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.AZ{}, err
	}
	for _, aData := range resp {
		if !t.checkRequiredAttributes(aData, attrs) {
			continue
		}
		state := aData.Get("ZoneState").MustString()
		if state != "AVAILABLE" {
			log.Infof("invalid az state (%s)", state, logger.NewORGPrefix(t.orgID))
			continue
		}
		zone := aData.Get("Zone").MustString()
		name := aData.Get("ZoneName").MustString()
		lcuuid := common.GetUUIDByOrgID(t.orgID, t.uuidGenerate+"_"+zone)
		azs = append(azs, model.AZ{
			Lcuuid:       lcuuid,
			Label:        zone,
			Name:         name,
			RegionLcuuid: t.regionLcuuid,
		})
		t.zoneToLcuuid[zone] = lcuuid
		zoneID, err := strconv.Atoi(aData.Get("ZoneId").MustString())
		if err != nil {
			log.Errorf("convert zone id to int failed: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
			continue
		}
		t.azIDToLcuuid[zoneID] = lcuuid
	}
	log.Debug("get azs complete", logger.NewORGPrefix(t.orgID))
	return azs, nil
}
