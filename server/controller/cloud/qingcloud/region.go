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

package qingcloud

import (
	"sort"
	"strings"

	"github.com/deckarep/golang-set"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) getRegionAndAZs() ([]model.Region, []model.AZ, error) {
	var retRegions []model.Region
	var retAZs []model.AZ
	var regionIdToLcuuid map[string]string
	var zoneNames []string

	log.Info("get region and azs starting")

	kwargs := []*Param{{"status.1", "active"}}
	response, err := q.GetResponse("DescribeZones", "zone_set", kwargs)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	regionIds := mapset.NewSet()
	regionIdToLcuuid = make(map[string]string)
	for _, r := range response {
		for i := range r.MustArray() {
			zone := r.GetIndex(i)
			err := q.CheckRequiredAttributes(zone, []string{"zone_id"})
			if err != nil {
				continue
			}

			zoneId := zone.Get("zone_id").MustString()
			// 亚太2区-A和雅加达区都是ap开头，但是不能合并为一个区域
			regionId := zoneId[:len(zoneId)-1]
			if strings.HasPrefix(regionId, "ap") {
				regionId = zoneId
			}
			regionLcuuid := common.GenerateUUID(q.UuidGenerate + "_" + regionId)
			retAZs = append(retAZs, model.AZ{
				Lcuuid:       common.GenerateUUID(q.UuidGenerate + "_" + zoneId),
				Name:         zoneId,
				Label:        zoneId,
				RegionLcuuid: q.GetRegionLcuuid(regionLcuuid),
			})
			zoneNames = append(zoneNames, zoneId)

			// 生成区域列表
			if q.RegionUuid == "" {
				regionIds.Add(regionId)
				regionIdToLcuuid[regionId] = regionLcuuid
			} else {
				regionIdToLcuuid[regionId] = q.RegionUuid
			}

		}
	}
	sort.Strings(zoneNames)
	q.RegionIdToLcuuid = regionIdToLcuuid
	q.ZoneNames = zoneNames

	// 生成区域返回数据
	for _, regionId := range regionIds.ToSlice() {
		regionIdStr := regionId.(string)
		retRegions = append(retRegions, model.Region{
			Lcuuid: common.GenerateUUID(q.UuidGenerate + "_" + regionIdStr),
			Name:   strings.ToUpper(regionIdStr),
		})
	}

	log.Info("get region and azs complete")
	return retRegions, retAZs, nil
}
