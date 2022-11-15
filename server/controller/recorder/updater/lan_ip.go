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
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/controller/recorder/db"
	"github.com/deepflowys/deepflow/server/controller/recorder/event"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type LANIP struct {
	UpdaterBase[cloudmodel.IP, mysql.LANIP, *cache.LANIP]
}

func NewLANIP(wholeCache *cache.Cache, cloudData []cloudmodel.IP, eventQueue *queue.OverwriteQueue) *LANIP {
	updater := &LANIP{
		UpdaterBase[cloudmodel.IP, mysql.LANIP, *cache.LANIP]{
			cache:        wholeCache,
			dbOperator:   db.NewLANIP(),
			diffBaseData: wholeCache.LANIPs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	updater.eventProducer = event.NewLANIP(&wholeCache.ToolDataSet, eventQueue)
	return updater
}

func (l *LANIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.IP) (diffBase *cache.LANIP, exists bool) {
	diffBase, exists = l.diffBaseData[cloudItem.Lcuuid]
	return
}

func (l *LANIP) generateDBItemToAdd(cloudItem *cloudmodel.IP) (*mysql.LANIP, bool) {
	vinterfaceID, exists := l.cache.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			common.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	networkID, exists := l.cache.GetNetworkIDByVInterfaceLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			common.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	ip := common.FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			common.RESOURCE_TYPE_LAN_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		))
		return nil, false
	}
	dbItem := &mysql.LANIP{
		IP:           ip,
		Domain:       l.cache.DomainLcuuid,
		SubDomain:    cloudItem.SubDomainLcuuid,
		NetworkID:    networkID,
		VInterfaceID: vinterfaceID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (l *LANIP) generateUpdateInfo(diffBase *cache.LANIP, cloudItem *cloudmodel.IP) (map[string]interface{}, bool) {
	return nil, false
}

func (l *LANIP) addCache(dbItems []*mysql.LANIP) {
	l.cache.AddLANIPs(dbItems)
}

// 保留接口
func (l *LANIP) updateCache(cloudItem *cloudmodel.IP, diffBase *cache.LANIP) {
}

func (l *LANIP) deleteCache(lcuuids []string) {
	l.cache.DeleteLANIPs(lcuuids)
}
