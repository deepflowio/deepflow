package updater

import (
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
	"github.com/metaflowys/metaflow/server/controller/recorder/db"
)

type LBTargetServer struct {
	UpdaterBase[cloudmodel.LBTargetServer, mysql.LBTargetServer, *cache.LBTargetServer]
}

func NewLBTargetServer(wholeCache *cache.Cache, cloudData []cloudmodel.LBTargetServer) *LBTargetServer {
	updater := &LBTargetServer{
		UpdaterBase[cloudmodel.LBTargetServer, mysql.LBTargetServer, *cache.LBTargetServer]{
			cache:        wholeCache,
			dbOperator:   db.NewLBTargetServer(),
			diffBaseData: wholeCache.LBTargetServers,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (s *LBTargetServer) getDiffBaseByCloudItem(cloudItem *cloudmodel.LBTargetServer) (diffBase *cache.LBTargetServer, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *LBTargetServer) generateDBItemToAdd(cloudItem *cloudmodel.LBTargetServer) (*mysql.LBTargetServer, bool) {
	lbID, exists := s.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			common.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	lbListenerID, exists := s.cache.ToolDataSet.GetLBListenerIDByLcuuid(cloudItem.LBListenerLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_LB_LISTENER_EN, cloudItem.LBListenerLcuuid,
			common.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	var vmID int
	if cloudItem.VMLcuuid != "" {
		vmID, exists = s.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
				common.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	vpcID, exists := s.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		))
	}

	dbItem := &mysql.LBTargetServer{
		LBID:         lbID,
		LBListenerID: lbListenerID,
		VMID:         vmID,
		VPCID:        vpcID,
		Domain:       s.cache.DomainLcuuid,
		Type:         cloudItem.Type,
		IP:           cloudItem.IP,
		Port:         cloudItem.Port,
		Protocol:     cloudItem.Protocol,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *LBTargetServer) generateUpdateInfo(diffBase *cache.LBTargetServer, cloudItem *cloudmodel.LBTargetServer) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.IP != cloudItem.IP {
		updateInfo["ip"] = cloudItem.IP
	}
	if diffBase.Port != cloudItem.Port {
		updateInfo["port"] = cloudItem.Port
	}
	if diffBase.Protocol != cloudItem.Protocol {
		updateInfo["protocol"] = cloudItem.Protocol
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (s *LBTargetServer) addCache(dbItems []*mysql.LBTargetServer) {
	s.cache.AddLBTargetServers(dbItems)
}

func (s *LBTargetServer) updateCache(cloudItem *cloudmodel.LBTargetServer, diffBase *cache.LBTargetServer) {
	diffBase.Update(cloudItem)
}

func (s *LBTargetServer) deleteCache(lcuuids []string) {
	s.cache.DeleteLBTargetServers(lcuuids)
}
