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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getAZs(sess *session.Session) ([]model.AZ, error) {
	log.Debug("get azs starting")
	var azs []model.AZ

	resp, err := ecs.New(sess).DescribeZones(&ecs.DescribeZonesInput{})
	if err != nil {
		log.Errorf("request volcengine (ecs.DescribeZones) api error: (%s)", err.Error())
		return []model.AZ{}, err
	}
	for _, zone := range resp.Zones {
		if zone == nil {
			continue
		}
		zoneID := v.getStringPointerValue(zone.ZoneId)
		lcuuid := common.GetUUIDByOrgID(v.orgID, zoneID)
		if _, ok := v.azLcuuids[lcuuid]; !ok {
			log.Debugf("az (%s) has no resource", zoneID)
			continue
		}
		azs = append(azs, model.AZ{
			Lcuuid:       lcuuid,
			Name:         zoneID,
			Label:        zoneID,
			RegionLcuuid: v.regionUUID,
		})
	}
	log.Debug("get azs complete")
	return azs, nil
}
