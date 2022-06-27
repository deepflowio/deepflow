package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type PeerConnection struct {
	UpdaterBase[cloudmodel.PeerConnection, mysql.PeerConnection, *cache.PeerConnection]
}

func NewPeerConnection(wholeCache *cache.Cache, cloudData []cloudmodel.PeerConnection) *PeerConnection {
	updater := &PeerConnection{
		UpdaterBase[cloudmodel.PeerConnection, mysql.PeerConnection, *cache.PeerConnection]{
			cache:        wholeCache,
			dbOperator:   db.NewPeerConnection(),
			diffBaseData: wholeCache.PeerConnections,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (c *PeerConnection) getDiffBaseByCloudItem(cloudItem *cloudmodel.PeerConnection) (diffBase *cache.PeerConnection, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *PeerConnection) generateDBItemToAdd(cloudItem *cloudmodel.PeerConnection) (*mysql.PeerConnection, bool) {
	remoteVPCID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.RemoteVPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.RemoteVPCLcuuid,
			common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	localVPCID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.LocalVPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.LocalVPCLcuuid,
			common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	remoteRegionID, exists := c.cache.ToolDataSet.GetRegionIDByLcuuid(cloudItem.RemoteRegionLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_REGION_EN, cloudItem.RemoteRegionLcuuid,
			common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	localRegionID, exists := c.cache.ToolDataSet.GetRegionIDByLcuuid(cloudItem.LocalRegionLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_REGION_EN, cloudItem.LocalRegionLcuuid,
			common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PeerConnection{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		Domain:         c.cache.DomainLcuuid,
		RemoteVPCID:    remoteVPCID,
		LocalVPCID:     localVPCID,
		RemoteRegionID: remoteRegionID,
		LocalRegionID:  localRegionID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *PeerConnection) generateUpdateInfo(diffBase *cache.PeerConnection, cloudItem *cloudmodel.PeerConnection) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.RemoteRegionLcuuid != cloudItem.RemoteRegionLcuuid {
		remoteRegionID, exists := c.cache.ToolDataSet.GetRegionIDByLcuuid(cloudItem.RemoteRegionLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_REGION_EN, cloudItem.RemoteRegionLcuuid,
				common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["remote_region_id"] = remoteRegionID
	}
	if diffBase.LocalRegionLcuuid != cloudItem.LocalRegionLcuuid {
		localRegionID, exists := c.cache.ToolDataSet.GetRegionIDByLcuuid(cloudItem.LocalRegionLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_REGION_EN, cloudItem.LocalRegionLcuuid,
				common.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["local_region_id"] = localRegionID
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (c *PeerConnection) addCache(dbItems []*mysql.PeerConnection) {
	c.cache.AddPeerConnections(dbItems)
}

func (c *PeerConnection) updateCache(cloudItem *cloudmodel.PeerConnection, diffBase *cache.PeerConnection) {
	diffBase.Update(cloudItem)
}

func (c *PeerConnection) deleteCache(lcuuids []string) {
	c.cache.DeletePeerConnections(lcuuids)
}
