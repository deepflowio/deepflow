package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type AZ struct {
	UpdaterBase[cloudmodel.AZ, mysql.AZ, *cache.AZ]
}

func NewAZ(wholeCache *cache.Cache, cloudData []cloudmodel.AZ) *AZ {
	updater := &AZ{
		UpdaterBase[cloudmodel.AZ, mysql.AZ, *cache.AZ]{
			cache:        wholeCache,
			dbOperator:   db.NewAZ(),
			diffBaseData: wholeCache.AZs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (z *AZ) getDiffBaseByCloudItem(cloudItem *cloudmodel.AZ) (diffBase *cache.AZ, exists bool) {
	diffBase, exists = z.diffBaseData[cloudItem.Lcuuid]
	return
}

func (z *AZ) generateDBItemToAdd(cloudItem *cloudmodel.AZ) (*mysql.AZ, bool) {
	dbItem := &mysql.AZ{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Region: cloudItem.RegionLcuuid,
		Domain: z.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (z *AZ) generateUpdateInfo(diffBase *cache.AZ, cloudItem *cloudmodel.AZ) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
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

func (z *AZ) addCache(dbItems []*mysql.AZ) {
	z.cache.AddAZs(dbItems)
}

func (z *AZ) updateCache(cloudItem *cloudmodel.AZ, diffBase *cache.AZ) {
	diffBase.Update(cloudItem)
}

func (z *AZ) deleteCache(lcuuids []string) {
	z.cache.DeleteAZs(lcuuids)
}
