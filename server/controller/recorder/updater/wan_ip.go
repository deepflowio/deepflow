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
	"strings"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type WANIP struct {
	UpdaterBase[cloudmodel.IP, mysql.WANIP, *cache.WANIP]
}

func NewWANIP(wholeCache *cache.Cache, domainToolDataSet *cache.ToolDataSet) *WANIP {
	updater := &WANIP{
		UpdaterBase[cloudmodel.IP, mysql.WANIP, *cache.WANIP]{
			cache:             wholeCache,
			domainToolDataSet: domainToolDataSet,
			dbOperator:        db.NewWANIP(),
			diffBaseData:      wholeCache.WANIPs,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (i *WANIP) SetCloudData(cloudData []cloudmodel.IP) {
	i.cloudData = cloudData
}

func (i *WANIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.IP) (diffBase *cache.WANIP, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *WANIP) generateDBItemToAdd(cloudItem *cloudmodel.IP) (*mysql.WANIP, bool) {
	vinterfaceID, exists := i.cache.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	subnetID, exists := i.cache.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
	if !exists {
		if i.domainToolDataSet != nil {
			subnetID, _ = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
		}
	}
	ip := FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		))
		return nil, false
	}
	dbItem := &mysql.WANIP{
		IP:           ip,
		Domain:       i.cache.DomainLcuuid,
		SubDomain:    cloudItem.SubDomainLcuuid,
		VInterfaceID: vinterfaceID,
		SubnetID:     subnetID,
		Region:       cloudItem.RegionLcuuid,
		ISP:          WAN_IP_ISP,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if strings.Contains(cloudItem.IP, ":") {
		dbItem.Netmask = IPV6_DEFAULT_NETMASK
		dbItem.Gateway = IPV6_DEFAULT_GATEWAY
	} else {
		dbItem.Netmask = IPV4_DEFAULT_NETMASK
		dbItem.Gateway = IPV4_DEFAULT_GATEWAY
	}
	return dbItem, true
}

func (i *WANIP) generateUpdateInfo(diffBase *cache.WANIP, cloudItem *cloudmodel.IP) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.SubnetLcuuid != cloudItem.SubnetLcuuid {
		subnetLcuuidsRepresentingNone := []string{"", "ffffffff-ffff-ffff-ffff-ffffffffffff", "94f0ca77-cb52-5869-98fb-2773ca4fb83f"}
		if common.Contains(subnetLcuuidsRepresentingNone, cloudItem.SubnetLcuuid) {
			updateInfo["vl2_net_id"] = 0
		} else {
			subnetID, exists := i.cache.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
			if !exists {
				if i.domainToolDataSet != nil {
					subnetID, exists = i.domainToolDataSet.GetSubnetIDByLcuuid(cloudItem.SubnetLcuuid)
				}
				if !exists {
					log.Error(resourceAForResourceBNotFound(
						RESOURCE_TYPE_SUBNET_EN, cloudItem.SubnetLcuuid,
						RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid,
					))
					return nil, false
				}
			}
			updateInfo["vl2_net_id"] = subnetID
		}
	}

	return updateInfo, len(updateInfo) > 0
}

func (i *WANIP) addCache(dbItems []*mysql.WANIP) {
	i.cache.AddWANIPs(dbItems)
}

func (i *WANIP) updateCache(cloudItem *cloudmodel.IP, diffBase *cache.WANIP) {
	diffBase.Update(cloudItem)
}

func (i *WANIP) deleteCache(lcuuids []string) {
	i.cache.DeleteWANIPs(lcuuids)
}
