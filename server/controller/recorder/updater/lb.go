package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type LB struct {
	UpdaterBase[cloudmodel.LB, mysql.LB, *cache.LB]
}

func NewLB(wholeCache *cache.Cache, cloudData []cloudmodel.LB) *LB {
	updater := &LB{
		UpdaterBase[cloudmodel.LB, mysql.LB, *cache.LB]{
			cache:        wholeCache,
			dbOperator:   db.NewLB(),
			diffBaseData: wholeCache.LBs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (l *LB) getDiffBaseByCloudItem(cloudItem *cloudmodel.LB) (diffBase *cache.LB, exists bool) {
	diffBase, exists = l.diffBaseData[cloudItem.Lcuuid]
	return
}

func (l *LB) generateDBItemToAdd(cloudItem *cloudmodel.LB) (*mysql.LB, bool) {
	vpcID, exists := l.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_LB_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.LB{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		UID:    cloudItem.Label,
		Model:  cloudItem.Model,
		VIP:    cloudItem.VIP,
		Domain: l.cache.DomainLcuuid,
		Region: cloudItem.RegionLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (l *LB) generateUpdateInfo(diffBase *cache.LB, cloudItem *cloudmodel.LB) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Model != cloudItem.Model {
		updateInfo["model"] = cloudItem.Model
	}
	if diffBase.VIP != cloudItem.VIP {
		updateInfo["vip"] = cloudItem.VIP
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (l *LB) addCache(dbItems []*mysql.LB) {
	l.cache.AddLBs(dbItems)
}

func (l *LB) updateCache(cloudItem *cloudmodel.LB, diffBase *cache.LB) {
	diffBase.Update(cloudItem)
}

func (l *LB) deleteCache(lcuuids []string) {
	l.cache.DeleteLBs(lcuuids)
}
