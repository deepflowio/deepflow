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

// NetworkMessageFactory Network资源的消息工厂
type NetworkMessageFactory struct{}

func (f *NetworkMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedNetworks{}
}

func (f *NetworkMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedNetwork{}
}

func (f *NetworkMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedNetworks{}
}

func (f *NetworkMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedNetworkFields{}
}

type Network struct {
	UpdaterBase[
		cloudmodel.Network,
		*diffbase.Network,
		*metadbmodel.Network,
		metadbmodel.Network,
	]
}

func NewNetwork(wholeCache *cache.Cache, cloudData []cloudmodel.Network) *Network {
	updater := &Network{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN,
			wholeCache,
			db.NewNetwork().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBases().Network().GetAll(),
			cloudData,
		),
	}
	updater.setDataGenerator(updater)

	if !hasMessageFactory(updater.resourceType) {
		RegisterMessageFactory(updater.resourceType, &NetworkMessageFactory{})
	}

	return updater
}

func (n *Network) generateDBItemToAdd(cloudItem *cloudmodel.Network) (*metadbmodel.Network, bool) {
	vpcItem := n.cache.Tool().Vpc().GetByLcuuid(cloudItem.VPCLcuuid)
	vpcID, exists := vpcItem.Id(), vpcItem.IsValid()
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
		), n.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.Network{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		State:          2,
		TunnelID:       cloudItem.TunnelID,
		SegmentationID: cloudItem.SegmentationID,
		Shared:         cloudItem.Shared,
		NetType:        cloudItem.NetType,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         n.metadata.GetDomainLcuuid(),
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
		VPCID:          vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *Network) generateUpdateInfo(diffBase *diffbase.Network, cloudItem *cloudmodel.Network) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedNetworkFields)
	mapInfo := make(map[string]interface{})
	if diffBase.VpcLcuuid != cloudItem.VPCLcuuid {
		vpcItem := n.cache.Tool().Vpc().GetByLcuuid(cloudItem.VPCLcuuid)
		vpcID, exists := vpcItem.Id(), vpcItem.IsValid()
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
			), n.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VpcId.SetNew(vpcID)
		structInfo.VpcLcuuid.Set(diffBase.VpcLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.TunnelId != cloudItem.TunnelID {
		mapInfo["tunnel_id"] = cloudItem.TunnelID
		structInfo.TunnelId.Set(diffBase.TunnelId, cloudItem.TunnelID)
	}
	if diffBase.SegmentationId != cloudItem.SegmentationID {
		mapInfo["segmentation_id"] = cloudItem.SegmentationID
		structInfo.SegmentationId.Set(diffBase.SegmentationId, cloudItem.SegmentationID)
	}
	if diffBase.NetType != cloudItem.NetType {
		mapInfo["net_type"] = cloudItem.NetType
		structInfo.NetType.Set(diffBase.NetType, cloudItem.NetType)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AzLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AzLcuuid.Set(diffBase.AzLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
