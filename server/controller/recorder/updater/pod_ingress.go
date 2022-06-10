package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type PodIngress struct {
	UpdaterBase[cloudmodel.PodIngress, mysql.PodIngress, *cache.PodIngress]
}

func NewPodIngress(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngress) *PodIngress {
	updater := &PodIngress{
		UpdaterBase[cloudmodel.PodIngress, mysql.PodIngress, *cache.PodIngress]{
			cache:        wholeCache,
			dbOperator:   db.NewPodIngress(),
			diffBaseData: wholeCache.PodIngresses,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (i *PodIngress) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngress) (diffBase *cache.PodIngress, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *PodIngress) generateDBItemToAdd(cloudItem *cloudmodel.PodIngress) (*mysql.PodIngress, bool) {
	podNamespaceID, exists := i.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := i.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodIngress{
		Name:           cloudItem.Name,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         i.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *PodIngress) generateUpdateInfo(diffBase *cache.PodIngress, cloudItem *cloudmodel.PodIngress) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
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

func (i *PodIngress) addCache(dbItems []*mysql.PodIngress) {
	i.cache.AddPodIngresses(dbItems)
}

func (i *PodIngress) updateCache(cloudItem *cloudmodel.PodIngress, diffBase *cache.PodIngress) {
	diffBase.Update(cloudItem)
}

func (i *PodIngress) deleteCache(lcuuids []string) {
	i.cache.DeletePodIngresses(lcuuids)
}
