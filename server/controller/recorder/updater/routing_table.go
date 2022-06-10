package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
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
