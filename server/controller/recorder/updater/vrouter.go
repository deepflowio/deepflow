package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type VRouter struct {
	UpdaterBase[cloudmodel.VRouter, mysql.VRouter, *cache.VRouter]
}

func NewVRouter(wholeCache *cache.Cache, cloudData []cloudmodel.VRouter) *VRouter {
	updater := &VRouter{
		UpdaterBase[cloudmodel.VRouter, mysql.VRouter, *cache.VRouter]{
			cache:        wholeCache,
			dbOperator:   db.NewVRouter(),
			diffBaseData: wholeCache.VRouters,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *VRouter) getDiffBaseByCloudItem(cloudItem *cloudmodel.VRouter) (diffBase *cache.VRouter, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *VRouter) generateDBItemToAdd(cloudItem *cloudmodel.VRouter) (*mysql.VRouter, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.VRouter{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		State:          common.VROUTER_STATE_RUNNING,
		GWLaunchServer: cloudItem.GWLaunchServer,
		Domain:         r.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		VPCID:          vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *VRouter) generateUpdateInfo(diffBase *cache.VRouter, cloudItem *cloudmodel.VRouter) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				common.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *VRouter) addCache(dbItems []*mysql.VRouter) {
	r.cache.AddVRouters(dbItems)
}

func (r *VRouter) updateCache(cloudItem *cloudmodel.VRouter, diffBase *cache.VRouter) {
	diffBase.Update(cloudItem)
}

func (r *VRouter) deleteCache(lcuuids []string) {
	r.cache.DeleteVRouters(lcuuids)
}
