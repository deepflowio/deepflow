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

type VMPodNodeConnection struct {
	UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *cache.VMPodNodeConnection]
}

func NewVMPodNodeConnection(wholeCache *cache.Cache, cloudData []cloudmodel.VMPodNodeConnection) *VMPodNodeConnection {
	updater := &VMPodNodeConnection{
		UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *cache.VMPodNodeConnection]{
			cache:        wholeCache,
			dbOperator:   db.NewVMPodNodeConnection(),
			diffBaseData: wholeCache.VMPodNodeConnections,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (c *VMPodNodeConnection) getDiffBaseByCloudItem(cloudItem *cloudmodel.VMPodNodeConnection) (diffBase *cache.VMPodNodeConnection, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *VMPodNodeConnection) generateDBItemToAdd(cloudItem *cloudmodel.VMPodNodeConnection) (*mysql.VMPodNodeConnection, bool) {
	vmID, exists := c.cache.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podNodeID, exists := c.cache.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_NODE_EN, cloudItem.PodNodeLcuuid,
			common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.VMPodNodeConnection{
		Domain:    c.cache.DomainLcuuid,
		SubDomain: cloudItem.SubDomainLcuuid,
		VMID:      vmID,
		PodNodeID: podNodeID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (c *VMPodNodeConnection) generateUpdateInfo(diffBase *cache.VMPodNodeConnection, cloudItem *cloudmodel.VMPodNodeConnection) (map[string]interface{}, bool) {
	return nil, false
}

func (c *VMPodNodeConnection) addCache(dbItems []*mysql.VMPodNodeConnection) {
	c.cache.AddVMPodNodeConnections(dbItems)
}

// 保留接口
func (c *VMPodNodeConnection) updateCache(cloudItem *cloudmodel.VMPodNodeConnection, diffBase *cache.VMPodNodeConnection) {
}

func (c *VMPodNodeConnection) deleteCache(lcuuids []string) {
	c.cache.DeleteVMPodNodeConnections(lcuuids)
}
