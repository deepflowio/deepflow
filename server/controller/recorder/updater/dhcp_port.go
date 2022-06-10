package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type DHCPPort struct {
	UpdaterBase[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]
}

func NewDHCPPort(wholeCache *cache.Cache, cloudData []cloudmodel.DHCPPort) *DHCPPort {
	updater := &DHCPPort{
		UpdaterBase[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]{
			cache:        wholeCache,
			dbOperator:   db.NewDHCPPort(),
			diffBaseData: wholeCache.DHCPPorts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (p *DHCPPort) getDiffBaseByCloudItem(cloudItem *cloudmodel.DHCPPort) (diffBase *cache.DHCPPort, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *DHCPPort) generateUpdateInfo(diffBase *cache.DHCPPort, cloudItem *cloudmodel.DHCPPort) (map[string]interface{}, bool) {
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

func (p *DHCPPort) generateDBItemToAdd(cloudItem *cloudmodel.DHCPPort) (*mysql.DHCPPort, bool) {
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.DHCPPort{
		Name:   cloudItem.Name,
		Domain: p.cache.DomainLcuuid,
		Region: cloudItem.RegionLcuuid,
		AZ:     cloudItem.AZLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *DHCPPort) addCache(dbItems []*mysql.DHCPPort) {
	p.cache.AddDHCPPorts(dbItems)
}

func (p *DHCPPort) updateCache(cloudItem *cloudmodel.DHCPPort, diffBase *cache.DHCPPort) {
	diffBase.Update(cloudItem)
}

func (p *DHCPPort) deleteCache(lcuuids []string) {
	p.cache.DeleteDHCPPorts(lcuuids)
}
