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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type RoutingTable struct {
	UpdaterBase[cloudmodel.RoutingTable, mysql.RoutingTable, *cache.RoutingTable]
}

func NewRoutingTable(wholeCache *cache.Cache, cloudData []cloudmodel.RoutingTable) *RoutingTable {
	updater := &RoutingTable{
		UpdaterBase[cloudmodel.RoutingTable, mysql.RoutingTable, *cache.RoutingTable]{
			cache:        wholeCache,
			dbOperator:   db.NewRoutingTable(),
			diffBaseData: wholeCache.RoutingTables,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (t *RoutingTable) getDiffBaseByCloudItem(cloudItem *cloudmodel.RoutingTable) (diffBase *cache.RoutingTable, exists bool) {
	diffBase, exists = t.diffBaseData[cloudItem.Lcuuid]
	return
}

func (t *RoutingTable) generateDBItemToAdd(cloudItem *cloudmodel.RoutingTable) (*mysql.RoutingTable, bool) {
	vrouterID, exists := t.cache.ToolDataSet.GetVRouterIDByLcuuid(cloudItem.VRouterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VROUTER_EN, cloudItem.VRouterLcuuid,
			common.RESOURCE_TYPE_ROUTING_TABLE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.RoutingTable{
		Destination: cloudItem.Destination,
		NexthopType: cloudItem.NexthopType,
		Nexthop:     cloudItem.Nexthop,
		VRouterID:   vrouterID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (t *RoutingTable) generateUpdateInfo(diffBase *cache.RoutingTable, cloudItem *cloudmodel.RoutingTable) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Destination != cloudItem.Destination {
		updateInfo["destination"] = cloudItem.Destination
	}
	if diffBase.NexthopType != cloudItem.NexthopType {
		updateInfo["nexthop_type"] = cloudItem.NexthopType
	}
	if diffBase.Nexthop != cloudItem.Nexthop {
		updateInfo["nexthop"] = cloudItem.Nexthop
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (t *RoutingTable) addCache(dbItems []*mysql.RoutingTable) {
	t.cache.AddRoutingTables(dbItems)
}

func (t *RoutingTable) updateCache(cloudItem *cloudmodel.RoutingTable, diffBase *cache.RoutingTable) {
	diffBase.Update(cloudItem)
}

func (t *RoutingTable) deleteCache(lcuuids []string) {
	t.cache.DeleteRoutingTables(lcuuids)
}
