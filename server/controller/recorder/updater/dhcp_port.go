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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type DHCPPort struct {
	UpdaterBase[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]
}

func NewDHCPPort(wholeCache *cache.Cache, cloudData []cloudmodel.DHCPPort) *DHCPPort {
	updater := &DHCPPort{
		UpdaterBase[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN,
			cache:        wholeCache,
			dbOperator:   db.NewDHCPPort(),
			diffBaseData: wholeCache.DHCPPorts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *DHCPPort) getDiffBaseByCloudItem(cloudItem *cloudmodel.DHCPPort) (diffBase *cache.DHCPPort, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *DHCPPort) generateUpdateInfo(diffBase *cache.DHCPPort, cloudItem *cloudmodel.DHCPPort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
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
