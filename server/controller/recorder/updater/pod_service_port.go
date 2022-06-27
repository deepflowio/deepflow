package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type PodServicePort struct {
	UpdaterBase[cloudmodel.PodServicePort, mysql.PodServicePort, *cache.PodServicePort]
}

func NewPodServicePort(wholeCache *cache.Cache, cloudData []cloudmodel.PodServicePort) *PodServicePort {
	updater := &PodServicePort{
		UpdaterBase[cloudmodel.PodServicePort, mysql.PodServicePort, *cache.PodServicePort]{
			cache:        wholeCache,
			dbOperator:   db.NewPodServicePort(),
			diffBaseData: wholeCache.PodServicePorts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (s *PodServicePort) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodServicePort) (diffBase *cache.PodServicePort, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodServicePort) generateDBItemToAdd(cloudItem *cloudmodel.PodServicePort) (*mysql.PodServicePort, bool) {
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			common.RESOURCE_TYPE_POD_SERVICE_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodServicePort{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Port:         cloudItem.Port,
		TargetPort:   cloudItem.TargetPort,
		NodePort:     cloudItem.NodePort,
		PodServiceID: podServiceID,
		SubDomain:    cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodServicePort) generateUpdateInfo(diffBase *cache.PodServicePort, cloudItem *cloudmodel.PodServicePort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (p *PodServicePort) addCache(dbItems []*mysql.PodServicePort) {
	p.cache.AddPodServicePorts(dbItems)
}

func (p *PodServicePort) updateCache(cloudItem *cloudmodel.PodServicePort, diffBase *cache.PodServicePort) {
	diffBase.Update(cloudItem)
}

func (p *PodServicePort) deleteCache(lcuuids []string) {
	p.cache.DeletePodServicePorts(lcuuids)
}
