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

// DHCPPortMessageFactory DHCPPort资源的消息工厂
type DHCPPortMessageFactory struct{}

func (f *DHCPPortMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedDHCPPorts{}
}

func (f *DHCPPortMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedDHCPPort{}
}

func (f *DHCPPortMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedDHCPPorts{}
}

func (f *DHCPPortMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedDHCPPortFields{}
}

type DHCPPort struct {
	UpdaterBase[
		cloudmodel.DHCPPort,
		*diffbase.DHCPPort,
		*metadbmodel.DHCPPort,
		metadbmodel.DHCPPort,
	]
}

func NewDHCPPort(wholeCache *cache.Cache, cloudData []cloudmodel.DHCPPort) *DHCPPort {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, &DHCPPortMessageFactory{})
	}

	updater := &DHCPPort{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN,
			wholeCache,
			db.NewDHCPPort().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.DHCPPorts,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (p *DHCPPort) generateDBItemToAdd(cloudItem *cloudmodel.DHCPPort) (*metadbmodel.DHCPPort, bool) {
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.DHCPPort{
		Name:   cloudItem.Name,
		Domain: p.metadata.GetDomainLcuuid(),
		Region: cloudItem.RegionLcuuid,
		AZ:     cloudItem.AZLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *DHCPPort) generateUpdateInfo(diffBase *diffbase.DHCPPort, cloudItem *cloudmodel.DHCPPort) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedDHCPPortFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
			), p.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID)
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
