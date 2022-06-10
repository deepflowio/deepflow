package updater

import (
	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
	"server/controller/recorder/common"
	"server/controller/recorder/db"
)

type VMPodNodeConnection struct {
	UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *cache.VMPodNodeConnection]
}

func NewVMPodNodeConnection(wholeCache *cache.Cache, cloudData []cloudmodel.VMPodNodeConnection) *VMPodNodeConnection {
	updater := &VMPodNodeConnection{
		UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *cache.VMPodNodeConnection]{
			cache:        wholeCache,
			dbOperator:   db.NewVMPodNodeConnection(),
			diffBaseData: wholeCache.VMPodNodeConnections,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (c *VMPodNodeConnection) getDiffBaseByCloudItem(cloudItem *cloudmodel.VMPodNodeConnection) (diffBase *cache.VMPodNodeConnection, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *VMPodNodeConnection) generateDBItemToAdd(cloudItem *cloudmodel.VMPodNodeConnection) (*mysql.VMPodNodeConnection, bool) {
	vmID, exists := c.cache.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podNodeID, exists := c.cache.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_NODE_EN, cloudItem.PodNodeLcuuid,
			common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.VMPodNodeConnection{
		Domain:    c.cache.DomainLcuuid,
		SubDomain: cloudItem.SubDomainLcuuid,
		VMID:      vmID,
		PodNodeID: podNodeID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (c *VMPodNodeConnection) generateUpdateInfo(diffBase *cache.VMPodNodeConnection, cloudItem *cloudmodel.VMPodNodeConnection) (map[string]interface{}, bool) {
	return nil, false
}

func (c *VMPodNodeConnection) addCache(dbItems []*mysql.VMPodNodeConnection) {
	c.cache.AddVMPodNodeConnections(dbItems)
}

// 保留接口
func (c *VMPodNodeConnection) updateCache(cloudItem *cloudmodel.VMPodNodeConnection, diffBase *cache.VMPodNodeConnection) {
}

func (c *VMPodNodeConnection) deleteCache(lcuuids []string) {
	c.cache.DeleteVMPodNodeConnections(lcuuids)
}
