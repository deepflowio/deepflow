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

package baidubce

import (
	"strings"

	"github.com/baidubce/bce-sdk-go/services/bcc"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getRegionAndAZs() ([]model.Region, []model.AZ, map[string]string, error) {
	var retRegions []model.Region
	var retAZs []model.AZ
	var zoneNameToAZLcuuid map[string]string

	log.Debug("get regions starting")

	bccClient, _ := bcc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	bccClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	result, err := bccClient.ListZone()
	if err != nil {
		log.Error(err)
		return nil, nil, nil, err
	}
	b.debugger.WriteJson("ListZone", " ", structToJson(result.Zones))
	zones := result.Zones

	regionName := ""
	if len(zones) > 1 {
		zoneName := zones[0].ZoneName
		regionName = zoneName[:strings.LastIndex(zoneName, "-")]
	} else {
		return nil, nil, nil, nil
	}
	regionLcuuid := common.GenerateUUID(regionName)
	retRegionLcuuid := regionLcuuid

	if b.regionUuid == "" {
		retRegion := model.Region{
			Lcuuid: regionLcuuid,
			Name:   regionName,
		}
		retRegions = append(retRegions, retRegion)
	} else {
		retRegionLcuuid = b.regionUuid
	}

	zoneNameToAZLcuuid = make(map[string]string)
	for _, zone := range zones {
		azLcuuid := common.GenerateUUID(regionLcuuid + zone.ZoneName)
		retAZ := model.AZ{
			Lcuuid:       azLcuuid,
			Name:         zone.ZoneName,
			RegionLcuuid: retRegionLcuuid,
		}
		retAZs = append(retAZs, retAZ)
		zoneNameToAZLcuuid[zone.ZoneName] = azLcuuid
	}

	log.Debug("get regions complete")
	return retRegions, retAZs, zoneNameToAZLcuuid, nil
}
