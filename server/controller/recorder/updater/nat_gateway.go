package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type NATGateway struct {
	UpdaterBase[cloudmodel.NATGateway, mysql.NATGateway, *cache.NATGateway]
}

func NewNATGateway(wholeCache *cache.Cache, cloudData []cloudmodel.NATGateway) *NATGateway {
	updater := &NATGateway{
		UpdaterBase[cloudmodel.NATGateway, mysql.NATGateway, *cache.NATGateway]{
			cache:        wholeCache,
			dbOperator:   db.NewNATGateway(),
			diffBaseData: wholeCache.NATGateways,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (g *NATGateway) getDiffBaseByCloudItem(cloudItem *cloudmodel.NATGateway) (diffBase *cache.NATGateway, exists bool) {
	diffBase, exists = g.diffBaseData[cloudItem.Lcuuid]
	return
}

func (g *NATGateway) generateDBItemToAdd(cloudItem *cloudmodel.NATGateway) (*mysql.NATGateway, bool) {
	vpcID, exists := g.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_NAT_GATEWAY_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.NATGateway{
		Name:        cloudItem.Name,
		Label:       cloudItem.Label,
		UID:         cloudItem.Label,
		FloatingIPs: cloudItem.FloatingIPs,
		Domain:      g.cache.DomainLcuuid,
		Region:      cloudItem.RegionLcuuid,
		VPCID:       vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (g *NATGateway) generateUpdateInfo(diffBase *cache.NATGateway, cloudItem *cloudmodel.NATGateway) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.FloatingIPs != cloudItem.FloatingIPs {
		updateInfo["floating_ips"] = cloudItem.FloatingIPs
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (g *NATGateway) addCache(dbItems []*mysql.NATGateway) {
	g.cache.AddNATGateways(dbItems)
}

func (g *NATGateway) updateCache(cloudItem *cloudmodel.NATGateway, diffBase *cache.NATGateway) {
	diffBase.Update(cloudItem)
}

func (g *NATGateway) deleteCache(lcuuids []string) {
	g.cache.DeleteNATGateways(lcuuids)
}
