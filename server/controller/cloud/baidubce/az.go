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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/bcc"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (b *BaiduBce) getAZs() ([]model.AZ, map[string]string, error) {
	var retAZs []model.AZ
	var zoneNameToAZLcuuid map[string]string

	log.Debug("get azs starting", logger.NewORGPrefix(b.orgID))

	bccClient, _ := bcc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	bccClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	startTime := time.Now()
	result, err := bccClient.ListZone()
	if err != nil {
		log.Error(err, logger.NewORGPrefix(b.orgID))
		return []model.AZ{}, map[string]string{}, err
	}
	b.cloudStatsd.RefreshAPIMoniter("ListZone", len(result.Zones), startTime)
	b.debugger.WriteJson("ListZone", " ", structToJson(result.Zones))
	zones := result.Zones

	zoneNameToAZLcuuid = make(map[string]string)
	for _, zone := range zones {
		azLcuuid := common.GenerateUUIDByOrgID(b.orgID, zone.ZoneName)
		retAZ := model.AZ{
			Lcuuid:       azLcuuid,
			Name:         zone.ZoneName,
			RegionLcuuid: b.regionLcuuid,
		}
		retAZs = append(retAZs, retAZ)
		zoneNameToAZLcuuid[zone.ZoneName] = azLcuuid
	}

	log.Debug("get azs complete", logger.NewORGPrefix(b.orgID))
	return retAZs, zoneNameToAZLcuuid, nil
}
