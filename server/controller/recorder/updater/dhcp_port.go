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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type DHCPPort struct {
	UpdaterBase[
		cloudmodel.DHCPPort,
		mysql.DHCPPort,
		*diffbase.DHCPPort, *message.DHCPPortAdd, message.DHCPPortAdd, *message.DHCPPortUpdate, message.DHCPPortUpdate, *message.DHCPPortFieldsUpdate, message.DHCPPortFieldsUpdate, *message.DHCPPortDelete, message.DHCPPortDelete]
}

func NewDHCPPort(wholeCache *cache.Cache, cloudData []cloudmodel.DHCPPort) *DHCPPort {
	updater := &DHCPPort{
		newUpdaterBase[
			cloudmodel.DHCPPort,
			mysql.DHCPPort,
			*diffbase.DHCPPort, *message.DHCPPortAdd, message.DHCPPortAdd, *message.DHCPPortUpdate, message.DHCPPortUpdate, *message.DHCPPortFieldsUpdate, message.DHCPPortFieldsUpdate, *message.DHCPPortDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN,
			wholeCache,
			db.NewDHCPPort(),
			wholeCache.DiffBaseDataSet.DHCPPorts,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (p *DHCPPort) getDiffBaseByCloudItem(cloudItem *cloudmodel.DHCPPort) (diffBase *diffbase.DHCPPort, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *DHCPPort) generateDBItemToAdd(cloudItem *cloudmodel.DHCPPort) (*mysql.DHCPPort, bool) {
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.DHCPPort{
		Name:   cloudItem.Name,
		Domain: p.cache.DomainLcuuid,
		Region: cloudItem.RegionLcuuid,
		AZ:     cloudItem.AZLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *DHCPPort) generateUpdateInfo(diffBase *diffbase.DHCPPort, cloudItem *cloudmodel.DHCPPort) (*message.DHCPPortFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.DHCPPortFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
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
