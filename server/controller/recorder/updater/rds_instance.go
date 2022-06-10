package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type RDSInstance struct {
	UpdaterBase[cloudmodel.RDSInstance, mysql.RDSInstance, *cache.RDSInstance]
}

func NewRDSInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RDSInstance) *RDSInstance {
	updater := &RDSInstance{
		UpdaterBase[cloudmodel.RDSInstance, mysql.RDSInstance, *cache.RDSInstance]{
			cache:        wholeCache,
			dbOperator:   db.NewRDSInstance(),
			diffBaseData: wholeCache.RDSInstances,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *RDSInstance) getDiffBaseByCloudItem(cloudItem *cloudmodel.RDSInstance) (diffBase *cache.RDSInstance, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *RDSInstance) generateDBItemToAdd(cloudItem *cloudmodel.RDSInstance) (*mysql.RDSInstance, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_RDS_INSTANCE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.RDSInstance{
		Name:    cloudItem.Name,
		Label:   cloudItem.Label,
		UID:     cloudItem.Label,
		State:   cloudItem.State,
		Type:    cloudItem.Type,
		Version: cloudItem.Version,
		Series:  cloudItem.Series,
		Model:   cloudItem.Model,
		Domain:  r.cache.DomainLcuuid,
		Region:  cloudItem.RegionLcuuid,
		AZ:      cloudItem.AZLcuuid,
		VPCID:   vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RDSInstance) generateUpdateInfo(diffBase *cache.RDSInstance, cloudItem *cloudmodel.RDSInstance) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.Series != cloudItem.Series {
		updateInfo["series"] = cloudItem.Series
	}
	if diffBase.Model != cloudItem.Model {
		updateInfo["model"] = cloudItem.Model
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *RDSInstance) addCache(dbItems []*mysql.RDSInstance) {
	r.cache.AddRDSInstances(dbItems)
}

func (r *RDSInstance) updateCache(cloudItem *cloudmodel.RDSInstance, diffBase *cache.RDSInstance) {
	diffBase.Update(cloudItem)
}

func (r *RDSInstance) deleteCache(lcuuids []string) {
	r.cache.DeleteRDSInstances(lcuuids)
}
