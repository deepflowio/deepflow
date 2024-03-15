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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type LANIP struct {
	UpdaterBase[
		cloudmodel.IP,
		mysql.LANIP,
		*diffbase.LANIP,
		*message.LANIPAdd,
		message.LANIPAdd,
		*message.LANIPUpdate,
		message.LANIPUpdate,
		*message.LANIPFieldsUpdate,
		message.LANIPFieldsUpdate,
		*message.LANIPDelete,
		message.LANIPDelete]
}

func NewLANIP(wholeCache *cache.Cache, domainToolDataSet *tool.DataSet) *LANIP {
	updater := &LANIP{
		newUpdaterBase[
			cloudmodel.IP,
			mysql.LANIP,
			*diffbase.LANIP,
			*message.LANIPAdd,
			message.LANIPAdd,
			*message.LANIPUpdate,
			message.LANIPUpdate,
			*message.LANIPFieldsUpdate,
			message.LANIPFieldsUpdate,
			*message.LANIPDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN,
			wholeCache,
			db.NewLANIP().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.LANIPs,
			nil,
		),
	}
	updater.setDomainToolDataSet(domainToolDataSet)
	updater.dataGenerator = updater
	return updater
}

func (i *LANIP) SetCloudData(cloudData []cloudmodel.IP) {
	i.cloudData = cloudData
}

func (i *LANIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.IP) (diffBase *diffbase.LANIP, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *LANIP) generateDBItemToAdd(cloudItem *cloudmodel.IP) (*mysql.LANIP, bool) {
	vinterfaceID, exists := i.cache.ToolDataSet.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	networkID, exists := i.cache.ToolDataSet.GetNetworkIDByVInterfaceLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		if i.domainToolDataSet != nil {
			networkID, exists = i.domainToolDataSet.GetNetworkIDByVInterfaceLcuuid(cloudItem.VInterfaceLcuuid)
		}
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
				ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	subnetID, exists := i.cache.ToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
	if !exists {
		if i.domainToolDataSet != nil {
			subnetID, exists = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
		}
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.SubnetLcuuid,
				ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	ip := rcommon.FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		))
		return nil, false
	}
	dbItem := &mysql.LANIP{
		IP:           ip,
		Domain:       i.cache.DomainLcuuid,
		SubDomain:    cloudItem.SubDomainLcuuid,
		NetworkID:    networkID,
		VInterfaceID: vinterfaceID,
		SubnetID:     subnetID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *LANIP) generateUpdateInfo(diffBase *diffbase.LANIP, cloudItem *cloudmodel.IP) (*message.LANIPFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.LANIPFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.SubnetLcuuid != cloudItem.SubnetLcuuid {
		subnetID, exists := i.cache.ToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
		if !exists {
			if i.domainToolDataSet != nil {
				subnetID, exists = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
			}
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.SubnetLcuuid,
					ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
				))
				return nil, nil, false
			}
		}
		mapInfo["vl2_net_id"] = subnetID
		structInfo.SubnetID.SetNew(mapInfo["vl2_net_id"].(int))
		structInfo.SubnetLcuuid.Set(diffBase.SubnetLcuuid, cloudItem.SubnetLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
