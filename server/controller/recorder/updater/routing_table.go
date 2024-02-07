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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type RoutingTable struct {
	UpdaterBase[
		cloudmodel.RoutingTable,
		mysql.RoutingTable,
		*diffbase.RoutingTable,
		*message.RoutingTableAdd,
		message.RoutingTableAdd,
		*message.RoutingTableUpdate,
		message.RoutingTableUpdate,
		*message.RoutingTableFieldsUpdate,
		message.RoutingTableFieldsUpdate,
		*message.RoutingTableDelete,
		message.RoutingTableDelete]
}

func NewRoutingTable(wholeCache *cache.Cache, cloudData []cloudmodel.RoutingTable) *RoutingTable {
	updater := &RoutingTable{
		newUpdaterBase[
			cloudmodel.RoutingTable,
			mysql.RoutingTable,
			*diffbase.RoutingTable,
			*message.RoutingTableAdd,
			message.RoutingTableAdd,
			*message.RoutingTableUpdate,
			message.RoutingTableUpdate,
			*message.RoutingTableFieldsUpdate,
			message.RoutingTableFieldsUpdate,
			*message.RoutingTableDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN,
			wholeCache,
			db.NewRoutingTable(),
			wholeCache.DiffBaseDataSet.RoutingTables,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (t *RoutingTable) getDiffBaseByCloudItem(cloudItem *cloudmodel.RoutingTable) (diffBase *diffbase.RoutingTable, exists bool) {
	diffBase, exists = t.diffBaseData[cloudItem.Lcuuid]
	return
}

func (t *RoutingTable) generateDBItemToAdd(cloudItem *cloudmodel.RoutingTable) (*mysql.RoutingTable, bool) {
	vrouterID, exists := t.cache.ToolDataSet.GetVRouterIDByLcuuid(cloudItem.VRouterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.VRouterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, cloudItem.Lcuuid,
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

func (t *RoutingTable) generateUpdateInfo(diffBase *diffbase.RoutingTable, cloudItem *cloudmodel.RoutingTable) (*message.RoutingTableFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.RoutingTableFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Destination != cloudItem.Destination {
		mapInfo["destination"] = cloudItem.Destination
		structInfo.Destination.Set(diffBase.Destination, cloudItem.Destination)
	}
	if diffBase.NexthopType != cloudItem.NexthopType {
		mapInfo["nexthop_type"] = cloudItem.NexthopType
		structInfo.NexthopType.Set(diffBase.NexthopType, cloudItem.NexthopType)
	}
	if diffBase.Nexthop != cloudItem.Nexthop {
		mapInfo["nexthop"] = cloudItem.Nexthop
		structInfo.Nexthop.Set(diffBase.Nexthop, cloudItem.Nexthop)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
