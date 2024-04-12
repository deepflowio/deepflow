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
	"strings"

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

type WANIP struct {
	UpdaterBase[
		cloudmodel.IP,
		mysql.WANIP,
		*diffbase.WANIP,
		*message.WANIPAdd,
		message.WANIPAdd,
		*message.WANIPUpdate,
		message.WANIPUpdate,
		*message.WANIPFieldsUpdate,
		message.WANIPFieldsUpdate,
		*message.WANIPDelete,
		message.WANIPDelete]
}

func NewWANIP(wholeCache *cache.Cache, domainToolDataSet *tool.DataSet) *WANIP {
	updater := &WANIP{
		newUpdaterBase[
			cloudmodel.IP,
			mysql.WANIP,
			*diffbase.WANIP,
			*message.WANIPAdd,
			message.WANIPAdd,
			*message.WANIPUpdate,
			message.WANIPUpdate,
			*message.WANIPFieldsUpdate,
			message.WANIPFieldsUpdate,
			*message.WANIPDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN,
			wholeCache,
			db.NewWANIP().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.WANIPs,
			nil,
		),
	}
	updater.setDomainToolDataSet(domainToolDataSet)
	updater.dataGenerator = updater
	return updater
}

func (i *WANIP) SetCloudData(cloudData []cloudmodel.IP) {
	i.cloudData = cloudData
}

func (i *WANIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.IP) (diffBase *diffbase.WANIP, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *WANIP) generateDBItemToAdd(cloudItem *cloudmodel.IP) (*mysql.WANIP, bool) {
	vinterfaceID, exists := i.cache.ToolDataSet.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	var subnetID int
	if cloudItem.SubnetLcuuid != "" {
		subnetID, exists = i.cache.ToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
		if !exists && i.domainToolDataSet != nil {
			subnetID, _ = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
		}
	}
	ip := rcommon.FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		))
		return nil, false
	}
	dbItem := &mysql.WANIP{
		IP:           ip,
		Domain:       i.metadata.Domain.Lcuuid,
		SubDomain:    cloudItem.SubDomainLcuuid,
		VInterfaceID: vinterfaceID,
		SubnetID:     subnetID,
		Region:       cloudItem.RegionLcuuid,
		ISP:          rcommon.WAN_IP_ISP,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if strings.Contains(cloudItem.IP, ":") {
		dbItem.Netmask = rcommon.IPV6_DEFAULT_NETMASK
		dbItem.Gateway = rcommon.IPV6_DEFAULT_GATEWAY
	} else {
		dbItem.Netmask = rcommon.IPV4_DEFAULT_NETMASK
		dbItem.Gateway = rcommon.IPV4_DEFAULT_GATEWAY
	}
	return dbItem, true
}

func (i *WANIP) generateUpdateInfo(diffBase *diffbase.WANIP, cloudItem *cloudmodel.IP) (*message.WANIPFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.WANIPFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.SubnetLcuuid != cloudItem.SubnetLcuuid {
		if cloudItem.SubnetLcuuid == "" {
			mapInfo["vl2_net_id"] = 0
		} else {
			subnetID, exists := i.cache.ToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
			if !exists {
				if i.domainToolDataSet != nil {
					subnetID, exists = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
				}
				if !exists {
					log.Error(resourceAForResourceBNotFound(
						ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.SubnetLcuuid,
						ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid,
					))
					return nil, nil, false
				}
			}
			mapInfo["vl2_net_id"] = subnetID
		}
		structInfo.SubnetID.SetNew(mapInfo["vl2_net_id"].(int))
		structInfo.SubnetLcuuid.Set(diffBase.SubnetLcuuid, cloudItem.SubnetLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
