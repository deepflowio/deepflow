/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type LBTargetServer struct {
	UpdaterBase[cloudmodel.LBTargetServer, mysql.LBTargetServer, *diffbase.LBTargetServer]
}

func NewLBTargetServer(wholeCache *cache.Cache, cloudData []cloudmodel.LBTargetServer) *LBTargetServer {
	updater := &LBTargetServer{
		UpdaterBase[cloudmodel.LBTargetServer, mysql.LBTargetServer, *diffbase.LBTargetServer]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN,
			cache:        wholeCache,
			dbOperator:   db.NewLBTargetServer(),
			diffBaseData: wholeCache.DiffBaseDataSet.LBTargetServers,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (s *LBTargetServer) getDiffBaseByCloudItem(cloudItem *cloudmodel.LBTargetServer) (diffBase *diffbase.LBTargetServer, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *LBTargetServer) generateDBItemToAdd(cloudItem *cloudmodel.LBTargetServer) (*mysql.LBTargetServer, bool) {
	lbID, exists := s.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	lbListenerID, exists := s.cache.ToolDataSet.GetLBListenerIDByLcuuid(cloudItem.LBListenerLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, cloudItem.LBListenerLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	var vmID int
	if cloudItem.VMLcuuid != "" {
		vmID, exists = s.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
				ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	vpcID, exists := s.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
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

func (s *LBTargetServer) generateUpdateInfo(diffBase *diffbase.LBTargetServer, cloudItem *cloudmodel.LBTargetServer) (map[string]interface{}, bool) {
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
