package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type CEN struct {
	UpdaterBase[cloudmodel.CEN, mysql.CEN, *cache.CEN]
}

func NewCEN(wholeCache *cache.Cache, cloudData []cloudmodel.CEN) *CEN {
	updater := &CEN{
		UpdaterBase[cloudmodel.CEN, mysql.CEN, *cache.CEN]{
			cache:        wholeCache,
			dbOperator:   db.NewCEN(),
			diffBaseData: wholeCache.CENs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (c *CEN) getDiffBaseByCloudItem(cloudItem *cloudmodel.CEN) (diffBase *cache.CEN, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *CEN) generateDBItemToAdd(cloudItem *cloudmodel.CEN) (*mysql.CEN, bool) {
	vpcIDs := []int{}
	for _, vpcLcuuid := range cloudItem.VPCLcuuids {
		vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(vpcLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
				common.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
			))
			continue
		}
		vpcIDs = append(vpcIDs, vpcID)
	}
	dbItem := &mysql.CEN{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Domain: c.cache.DomainLcuuid,
		VPCIDs: common.IntArrayToString(vpcIDs),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *CEN) generateUpdateInfo(diffBase *cache.CEN, cloudItem *cloudmodel.CEN) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if !common.AreElementsSameInTwoArray(diffBase.VPCLcuuids, cloudItem.VPCLcuuids) {
		vpcIDs := []int{}
		for _, vpcLcuuid := range cloudItem.VPCLcuuids {
			vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(vpcLcuuid)
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					common.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
					common.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
				))
				continue
			}
			vpcIDs = append(vpcIDs, vpcID)
		}
		updateInfo["epc_ids"] = vpcIDs
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (c *CEN) addCache(dbItems []*mysql.CEN) {
	c.cache.AddCENs(dbItems)
}

func (c *CEN) updateCache(cloudItem *cloudmodel.CEN, diffBase *cache.CEN) {
	diffBase.Update(cloudItem)
}

func (c *CEN) deleteCache(lcuuids []string) {
	c.cache.DeleteCENs(lcuuids)
}
