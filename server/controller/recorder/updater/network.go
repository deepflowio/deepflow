/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type Network struct {
	UpdaterBase[
		cloudmodel.Network,
		mysql.Network,
		*diffbase.Network,
		*message.NetworkAdd,
		message.NetworkAdd,
		*message.NetworkUpdate,
		message.NetworkUpdate,
		*message.NetworkFieldsUpdate,
		message.NetworkFieldsUpdate,
		*message.NetworkDelete,
		message.NetworkDelete]
}

func NewNetwork(wholeCache *cache.Cache, cloudData []cloudmodel.Network) *Network {
	updater := &Network{
		newUpdaterBase[
			cloudmodel.Network,
			mysql.Network,
			*diffbase.Network,
			*message.NetworkAdd,
			message.NetworkAdd,
			*message.NetworkUpdate,
			message.NetworkUpdate,
			*message.NetworkFieldsUpdate,
			message.NetworkFieldsUpdate,
			*message.NetworkDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN,
			wholeCache,
			db.NewNetwork(),
			wholeCache.DiffBaseDataSet.Networks,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (n *Network) getDiffBaseByCloudItem(cloudItem *cloudmodel.Network) (diffBase *diffbase.Network, exists bool) {
	diffBase, exists = n.diffBaseData[cloudItem.Lcuuid]
	return
}

func (n *Network) generateDBItemToAdd(cloudItem *cloudmodel.Network) (*mysql.Network, bool) {
	vpcID, exists := n.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.Network{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		State:          2,
		TunnelID:       cloudItem.TunnelID,
		SegmentationID: cloudItem.SegmentationID,
		Shared:         cloudItem.Shared,
		NetType:        cloudItem.NetType,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         n.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
		VPCID:          vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *Network) generateUpdateInfo(diffBase *diffbase.Network, cloudItem *cloudmodel.Network) (*message.NetworkFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.NetworkFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := n.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
			))
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
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.TunnelID != cloudItem.TunnelID {
		mapInfo["tunnel_id"] = cloudItem.TunnelID
		structInfo.TunnelID.Set(diffBase.TunnelID, cloudItem.TunnelID)
	}
	if diffBase.SegmentationID != cloudItem.SegmentationID {
		mapInfo["segmentation_id"] = cloudItem.SegmentationID
		structInfo.SegmentationID.Set(diffBase.SegmentationID, cloudItem.SegmentationID)
	}
	if diffBase.NetType != cloudItem.NetType {
		mapInfo["net_type"] = cloudItem.NetType
		structInfo.NetType.Set(diffBase.NetType, cloudItem.NetType)
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
