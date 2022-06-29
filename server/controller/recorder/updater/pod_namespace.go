package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type PodNamespace struct {
	UpdaterBase[cloudmodel.PodNamespace, mysql.PodNamespace, *cache.PodNamespace]
}

func NewPodNamespace(wholeCache *cache.Cache, cloudData []cloudmodel.PodNamespace) *PodNamespace {
	updater := &PodNamespace{
		UpdaterBase[cloudmodel.PodNamespace, mysql.PodNamespace, *cache.PodNamespace]{
			cache:        wholeCache,
			dbOperator:   db.NewPodNamespace(),
			diffBaseData: wholeCache.PodNamespaces,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (n *PodNamespace) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodNamespace) (diffBase *cache.PodNamespace, exists bool) {
	diffBase, exists = n.diffBaseData[cloudItem.Lcuuid]
	return
}

func (n *PodNamespace) generateDBItemToAdd(cloudItem *cloudmodel.PodNamespace) (*mysql.PodNamespace, bool) {
	podClusterID, exists := n.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodNamespace{
		Name:         cloudItem.Name,
		PodClusterID: podClusterID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       n.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *PodNamespace) generateUpdateInfo(diffBase *cache.PodNamespace, cloudItem *cloudmodel.PodNamespace) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
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

func (n *PodNamespace) addCache(dbItems []*mysql.PodNamespace) {
	n.cache.AddPodNamespaces(dbItems)
}

func (n *PodNamespace) updateCache(cloudItem *cloudmodel.PodNamespace, diffBase *cache.PodNamespace) {
	diffBase.Update(cloudItem)
}

func (n *PodNamespace) deleteCache(lcuuids []string) {
	n.cache.DeletePodNamespaces(lcuuids)
}
