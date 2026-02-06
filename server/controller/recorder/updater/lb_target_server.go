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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// LBTargetServerMessageFactory LBTargetServer资源的消息工厂
type LBTargetServerMessageFactory struct{}

func (f *LBTargetServerMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedLBTargetServers{}
}

func (f *LBTargetServerMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedLBTargetServer{}
}

func (f *LBTargetServerMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedLBTargetServers{}
}

func (f *LBTargetServerMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedLBTargetServerFields{}
}

type LBTargetServer struct {
	UpdaterBase[
		cloudmodel.LBTargetServer,
		*diffbase.LBTargetServer,
		*metadbmodel.LBTargetServer,
		metadbmodel.LBTargetServer,
	]
}

func NewLBTargetServer(wholeCache *cache.Cache, cloudData []cloudmodel.LBTargetServer) *LBTargetServer {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, &LBTargetServerMessageFactory{})
	}

	updater := &LBTargetServer{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN,
			wholeCache,
			db.NewLBTargetServer().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.LBTargetServers,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (s *LBTargetServer) generateDBItemToAdd(cloudItem *cloudmodel.LBTargetServer) (*metadbmodel.LBTargetServer, bool) {
	lbID, exists := s.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
		return nil, false
	}
	lbListenerID, exists := s.cache.ToolDataSet.GetLBListenerIDByLcuuid(cloudItem.LBListenerLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, cloudItem.LBListenerLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
		return nil, false
	}
	var vmID int
	if cloudItem.VMLcuuid != "" {
		vmID, exists = s.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
				ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
			), s.metadata.LogPrefixes)
			return nil, false
		}
	}
	vpcID, exists := s.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
	}
	dbItem := &metadbmodel.LBTargetServer{
		LBID:         lbID,
		LBListenerID: lbListenerID,
		VMID:         vmID,
		VPCID:        vpcID,
		Domain:       s.metadata.GetDomainLcuuid(),
		Type:         cloudItem.Type,
		IP:           cloudItem.IP,
		Port:         cloudItem.Port,
		Protocol:     cloudItem.Protocol,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *LBTargetServer) generateUpdateInfo(diffBase *diffbase.LBTargetServer, cloudItem *cloudmodel.LBTargetServer) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedLBTargetServerFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.IP != cloudItem.IP {
		mapInfo["ip"] = cloudItem.IP
		structInfo.IP.Set(diffBase.IP, cloudItem.IP)
	}
	if diffBase.Port != cloudItem.Port {
		mapInfo["port"] = cloudItem.Port
		structInfo.Port.Set(diffBase.Port, cloudItem.Port)
	}
	if diffBase.Protocol != cloudItem.Protocol {
		mapInfo["protocol"] = cloudItem.Protocol
		structInfo.Protocol.Set(diffBase.Protocol, cloudItem.Protocol)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
