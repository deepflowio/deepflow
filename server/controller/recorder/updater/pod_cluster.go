package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type PodCluster struct {
	UpdaterBase[cloudmodel.PodCluster, mysql.PodCluster, *cache.PodCluster]
}

func NewPodCluster(wholeCache *cache.Cache, cloudData []cloudmodel.PodCluster) *PodCluster {
	updater := &PodCluster{
		UpdaterBase[cloudmodel.PodCluster, mysql.PodCluster, *cache.PodCluster]{
			cache:        wholeCache,
			dbOperator:   db.NewPodCluster(),
			diffBaseData: wholeCache.PodClusters,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (c *PodCluster) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodCluster) (diffBase *cache.PodCluster, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *PodCluster) generateDBItemToAdd(cloudItem *cloudmodel.PodCluster) (*mysql.PodCluster, bool) {
	vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodCluster{
		Name:        cloudItem.Name,
		Version:     cloudItem.Version,
		ClusterName: cloudItem.ClusterName,
		SubDomain:   cloudItem.SubDomainLcuuid,
		Domain:      c.cache.DomainLcuuid,
		Region:      cloudItem.RegionLcuuid,
		AZ:          cloudItem.AZLcuuid,
		VPCID:       vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *PodCluster) generateUpdateInfo(diffBase *cache.PodCluster, cloudItem *cloudmodel.PodCluster) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.ClusterName != cloudItem.ClusterName {
		updateInfo["cluster_name"] = cloudItem.ClusterName
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

func (c *PodCluster) addCache(dbItems []*mysql.PodCluster) {
	c.cache.AddPodClusters(dbItems)
}

func (c *PodCluster) updateCache(cloudItem *cloudmodel.PodCluster, diffBase *cache.PodCluster) {
	diffBase.Update(cloudItem)
}

func (c *PodCluster) deleteCache(lcuuids []string) {
	c.cache.DeletePodClusters(lcuuids)
}
