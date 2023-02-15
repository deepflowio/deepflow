/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type Network struct {
	UpdaterBase[cloudmodel.Network, mysql.Network, *cache.Network]
}

func NewNetwork(wholeCache *cache.Cache, cloudData []cloudmodel.Network) *Network {
	updater := &Network{
		UpdaterBase[cloudmodel.Network, mysql.Network, *cache.Network]{
			cache:        wholeCache,
			dbOperator:   db.NewNetwork(),
			diffBaseData: wholeCache.Networks,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (n *Network) getDiffBaseByCloudItem(cloudItem *cloudmodel.Network) (diffBase *cache.Network, exists bool) {
	diffBase, exists = n.diffBaseData[cloudItem.Lcuuid]
	return
}

func (n *Network) generateDBItemToAdd(cloudItem *cloudmodel.Network) (*mysql.Network, bool) {
	vpcID, exists := n.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			common.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
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

func (n *Network) generateUpdateInfo(diffBase *cache.Network, cloudItem *cloudmodel.Network) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := n.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				common.RESOURCE_TYPE_NETWORK_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.TunnelID != cloudItem.TunnelID {
		updateInfo["tunnel_id"] = cloudItem.TunnelID
	}
	if diffBase.SegmentationID != cloudItem.SegmentationID {
		updateInfo["segmentation_id"] = cloudItem.SegmentationID
	}
	if diffBase.NetType != cloudItem.NetType {
		updateInfo["net_type"] = cloudItem.NetType
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

func (n *Network) addCache(dbItems []*mysql.Network) {
	n.cache.AddNetworks(dbItems)
}

func (n *Network) updateCache(cloudItem *cloudmodel.Network, diffBase *cache.Network) {
	diffBase.Update(cloudItem)
	n.cache.UpdateNetwork(cloudItem)
}

func (n *Network) deleteCache(lcuuids []string) {
	n.cache.DeleteNetworks(lcuuids)
}
