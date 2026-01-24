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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// RoutingTableMessageFactory RoutingTable资源的消息工厂
type RoutingTableMessageFactory struct{}

func (f *RoutingTableMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedRoutingTables{}
}

func (f *RoutingTableMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedRoutingTable{}
}

func (f *RoutingTableMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedRoutingTables{}
}

func (f *RoutingTableMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedRoutingTableFields{}
}

type RoutingTable struct {
	UpdaterBase[cloudmodel.RoutingTable, *diffbase.RoutingTable, *metadbmodel.RoutingTable, metadbmodel.RoutingTable]
}

func NewRoutingTable(wholeCache *cache.Cache, cloudData []cloudmodel.RoutingTable) *RoutingTable {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, &RoutingTableMessageFactory{})
	}

	updater := &RoutingTable{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN,
			wholeCache,
			db.NewRoutingTable().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.RoutingTables,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

func (t *RoutingTable) generateDBItemToAdd(cloudItem *cloudmodel.RoutingTable) (*metadbmodel.RoutingTable, bool) {
	vrouterID, exists := t.cache.ToolDataSet.GetVRouterIDByLcuuid(cloudItem.VRouterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.VRouterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, cloudItem.Lcuuid,
		), t.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.RoutingTable{
		Destination: cloudItem.Destination,
		NexthopType: cloudItem.NexthopType,
		Nexthop:     cloudItem.Nexthop,
		VRouterID:   vrouterID,
		Domain:      t.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (t *RoutingTable) generateUpdateInfo(diffBase *diffbase.RoutingTable, cloudItem *cloudmodel.RoutingTable) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedRoutingTableFields{}
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

	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
