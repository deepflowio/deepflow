/*
 * Copyright (c) 2023 Yunshan Networks
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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChRegion struct {
	UpdaterBase[mysql.ChRegion, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChRegion(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChRegion {
	updater := &ChRegion{
		UpdaterBase[mysql.ChRegion, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_REGION,
		},
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (r *ChRegion) generateNewData() (map[IDKey]mysql.ChRegion, bool) {
	log.Infof("generate data for %s", r.resourceTypeName)
	var regions []mysql.Region
	var azs []mysql.AZ
	var vpcs []mysql.VPC
	err := mysql.Db.Unscoped().Find(&regions).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(r.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&azs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(r.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&vpcs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(r.resourceTypeName, err))
		return nil, false
	}

	regionLcuuidToDomainLcuuids := make(map[string]map[string]bool)
	for _, az := range azs {
		_, ok := regionLcuuidToDomainLcuuids[az.Region]
		if !ok {
			regionLcuuidToDomainLcuuids[az.Region] = map[string]bool{}
		}
		if az.Domain != "" && az.Domain != common.DEFAULT_REGION && az.Region != "" {
			regionLcuuidToDomainLcuuids[az.Region][az.Domain] = true
		}
	}
	for _, vpc := range vpcs {
		_, ok := regionLcuuidToDomainLcuuids[vpc.Region]
		if !ok {
			regionLcuuidToDomainLcuuids[vpc.Region] = map[string]bool{}
		}
		if vpc.Domain != "" && vpc.Domain != common.DEFAULT_REGION && vpc.Region != "" {
			regionLcuuidToDomainLcuuids[vpc.Region][vpc.Domain] = true
		}
	}
	keyToItem := make(map[IDKey]mysql.ChRegion)
	for _, region := range regions {
		domainLcuuids, _ := regionLcuuidToDomainLcuuids[region.Lcuuid]
		domainIconIDs := []int{}
		for domainLcuuid, _ := range domainLcuuids {
			domainIconId := r.domainLcuuidToIconID[domainLcuuid]
			if domainIconId != 0 {
				domainIconIDs = append(domainIconIDs, domainIconId)
			}
		}
		var iconID int
		if len(domainIconIDs) == 1 {
			iconID = domainIconIDs[0]
		}
		// TODO icon id为0，应该不需要特殊处理，可以直接存储？
		if iconID == 0 {
			iconID = r.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_REGION}]
		}

		if region.DeletedAt.Valid {
			keyToItem[IDKey{ID: region.ID}] = mysql.ChRegion{
				ID:     region.ID,
				Name:   region.Name + " (deleted)",
				IconID: iconID,
			}
		} else {
			keyToItem[IDKey{ID: region.ID}] = mysql.ChRegion{
				ID:     region.ID,
				Name:   region.Name,
				IconID: iconID,
			}
		}
	}
	return keyToItem, true
}

func (r *ChRegion) generateKey(dbItem mysql.ChRegion) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (r *ChRegion) generateUpdateInfo(oldItem, newItem mysql.ChRegion) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
