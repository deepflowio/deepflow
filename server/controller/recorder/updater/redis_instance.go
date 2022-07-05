package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type RedisInstance struct {
	UpdaterBase[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]
}

func NewRedisInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RedisInstance) *RedisInstance {
	updater := &RedisInstance{
		UpdaterBase[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]{
			cache:        wholeCache,
			dbOperator:   db.NewRedisInstance(),
			diffBaseData: wholeCache.RedisInstances,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *RedisInstance) getDiffBaseByCloudItem(cloudItem *cloudmodel.RedisInstance) (diffBase *cache.RedisInstance, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *RedisInstance) generateDBItemToAdd(cloudItem *cloudmodel.RedisInstance) (*mysql.RedisInstance, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_REDIS_INSTANCE_EN, cloudItem.Lcuuid,
		)
		return nil, false
	}
	dbItem := &mysql.RedisInstance{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		UID:          cloudItem.Label,
		State:        cloudItem.State,
		Version:      cloudItem.Version,
		InternalHost: cloudItem.InternalHost,
		PublicHost:   cloudItem.PublicHost,
		Domain:       r.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RedisInstance) generateUpdateInfo(diffBase *cache.RedisInstance, cloudItem *cloudmodel.RedisInstance) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.PublicHost != cloudItem.PublicHost {
		updateInfo["public_host"] = cloudItem.PublicHost
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *RedisInstance) addCache(dbItems []*mysql.RedisInstance) {
	r.cache.AddRedisInstances(dbItems)
}

func (r *RedisInstance) updateCache(cloudItem *cloudmodel.RedisInstance, diffBase *cache.RedisInstance) {
	diffBase.Update(cloudItem)
}

func (r *RedisInstance) deleteCache(lcuuids []string) {
	r.cache.DeleteRedisInstances(lcuuids)
}
