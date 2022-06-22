package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/db"
)

type Region struct {
	UpdaterBase[cloudmodel.Region, mysql.Region, *cache.Region]
}

func NewRegion(wholeCache *cache.Cache, cloudData []cloudmodel.Region) *Region {
	updater := &Region{
		UpdaterBase[cloudmodel.Region, mysql.Region, *cache.Region]{
			cache:        wholeCache,
			dbOperator:   db.NewRegion(),
			diffBaseData: wholeCache.Regions,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *Region) getDiffBaseByCloudItem(cloudItem *cloudmodel.Region) (diffBase *cache.Region, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *Region) generateDBItemToAdd(cloudItem *cloudmodel.Region) (*mysql.Region, bool) {
	dbItem := &mysql.Region{
		Name:  cloudItem.Name,
		Label: cloudItem.Label,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *Region) generateUpdateInfo(diffBase *cache.Region, cloudItem *cloudmodel.Region) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *Region) addCache(dbItems []*mysql.Region) {
	r.cache.AddRegions(dbItems)
}

func (r *Region) updateCache(cloudItem *cloudmodel.Region, diffBase *cache.Region) {
	diffBase.Update(cloudItem)
}

func (r *Region) deleteCache(lcuuids []string) {
	r.cache.DeleteRegions(lcuuids)
}
