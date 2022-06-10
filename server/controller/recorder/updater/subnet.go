package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type Subnet struct {
	UpdaterBase[cloudmodel.Subnet, mysql.Subnet, *cache.Subnet]
}

func NewSubnet(wholeCache *cache.Cache, cloudData []cloudmodel.Subnet) *Subnet {
	updater := &Subnet{
		UpdaterBase[cloudmodel.Subnet, mysql.Subnet, *cache.Subnet]{
			cache:        wholeCache,
			dbOperator:   db.NewSubnet(),
			diffBaseData: wholeCache.Subnets,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (s *Subnet) getDiffBaseByCloudItem(cloudItem *cloudmodel.Subnet) (diffBase *cache.Subnet, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *Subnet) generateDBItemToAdd(cloudItem *cloudmodel.Subnet) (*mysql.Subnet, bool) {
	networkID, exists := s.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			common.RESOURCE_TYPE_SUBNET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	prefix, netmask, err := common.CIDRToPreNetMask(cloudItem.CIDR)
	if err != nil {
		log.Errorf("convert %s cidr: %s failed: %v", common.RESOURCE_TYPE_SUBNET_EN, cloudItem.CIDR, err)
		return nil, false
	}

	dbItem := &mysql.Subnet{
		Name:      cloudItem.Name,
		Label:     cloudItem.Label,
		Prefix:    prefix,
		Netmask:   netmask,
		SubDomain: cloudItem.SubDomainLcuuid,
		NetworkID: networkID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *Subnet) generateUpdateInfo(diffBase *cache.Subnet, cloudItem *cloudmodel.Subnet) (map[string]interface{}, bool) {
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

func (s *Subnet) addCache(dbItems []*mysql.Subnet) {
	s.cache.AddSubnets(dbItems)
}

func (s *Subnet) updateCache(cloudItem *cloudmodel.Subnet, diffBase *cache.Subnet) {
	diffBase.Update(cloudItem)
}

func (s *Subnet) deleteCache(lcuuids []string) {
	s.cache.DeleteSubnets(lcuuids)
}
