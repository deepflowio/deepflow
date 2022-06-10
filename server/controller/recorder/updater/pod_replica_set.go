package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type PodReplicaSet struct {
	UpdaterBase[cloudmodel.PodReplicaSet, mysql.PodReplicaSet, *cache.PodReplicaSet]
}

func NewPodReplicaSet(wholeCache *cache.Cache, cloudData []cloudmodel.PodReplicaSet) *PodReplicaSet {
	updater := &PodReplicaSet{
		UpdaterBase[cloudmodel.PodReplicaSet, mysql.PodReplicaSet, *cache.PodReplicaSet]{
			cache:        wholeCache,
			dbOperator:   db.NewPodReplicaSet(),
			diffBaseData: wholeCache.PodReplicaSets,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *PodReplicaSet) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodReplicaSet) (diffBase *cache.PodReplicaSet, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *PodReplicaSet) generateDBItemToAdd(cloudItem *cloudmodel.PodReplicaSet) (*mysql.PodReplicaSet, bool) {
	podNamespaceID, exists := r.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			common.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := r.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			common.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podGroupID, exists := r.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			common.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodReplicaSet{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		PodClusterID:   podClusterID,
		PodGroupID:     podGroupID,
		PodNamespaceID: podNamespaceID,
		PodNum:         cloudItem.PodNum,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         r.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *PodReplicaSet) generateUpdateInfo(diffBase *cache.PodReplicaSet, cloudItem *cloudmodel.PodReplicaSet) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.PodNum != cloudItem.PodNum {
		updateInfo["pod_num"] = cloudItem.PodNum
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *PodReplicaSet) addCache(dbItems []*mysql.PodReplicaSet) {
	r.cache.AddPodReplicaSets(dbItems)
}

func (r *PodReplicaSet) updateCache(cloudItem *cloudmodel.PodReplicaSet, diffBase *cache.PodReplicaSet) {
	diffBase.Update(cloudItem)
}

func (r *PodReplicaSet) deleteCache(lcuuids []string) {
	r.cache.DeletePodReplicaSets(lcuuids)
}
