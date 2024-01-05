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
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type FloatingIP struct {
	UpdaterBase[cloudmodel.FloatingIP, mysql.FloatingIP, *diffbase.FloatingIP]
}

func NewFloatingIP(wholeCache *cache.Cache, cloudData []cloudmodel.FloatingIP) *FloatingIP {
	updater := &FloatingIP{
		UpdaterBase[cloudmodel.FloatingIP, mysql.FloatingIP, *diffbase.FloatingIP]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN,
			cache:        wholeCache,
			dbOperator:   db.NewFloatingIP(),
			diffBaseData: wholeCache.DiffBaseDataSet.FloatingIPs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (f *FloatingIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.FloatingIP) (diffBase *diffbase.FloatingIP, exists bool) {
	diffBase, exists = f.diffBaseData[cloudItem.Lcuuid]
	return
}

func (f *FloatingIP) generateDBItemToAdd(cloudItem *cloudmodel.FloatingIP) (*mysql.FloatingIP, bool) {
	networkID, exists := f.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	vmID, exists := f.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	vpcID, exists := f.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	ip := rcommon.FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		))
		return nil, false
	}
	dbItem := &mysql.FloatingIP{
		Domain:    f.cache.DomainLcuuid,
		Region:    cloudItem.RegionLcuuid,
		IP:        ip,
		NetworkID: networkID,
		VPCID:     vpcID,
		VMID:      vmID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (f *FloatingIP) generateUpdateInfo(diffBase *diffbase.FloatingIP, cloudItem *cloudmodel.FloatingIP) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := f.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	return updateInfo, len(updateInfo) > 0
}
