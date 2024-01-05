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
)

type VMPodNodeConnection struct {
	UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *diffbase.VMPodNodeConnection]
}

func NewVMPodNodeConnection(wholeCache *cache.Cache, cloudData []cloudmodel.VMPodNodeConnection) *VMPodNodeConnection {
	updater := &VMPodNodeConnection{
		UpdaterBase[cloudmodel.VMPodNodeConnection, mysql.VMPodNodeConnection, *diffbase.VMPodNodeConnection]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN,
			cache:        wholeCache,
			dbOperator:   db.NewVMPodNodeConnection(),
			diffBaseData: wholeCache.DiffBaseDataSet.VMPodNodeConnections,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (c *VMPodNodeConnection) getDiffBaseByCloudItem(cloudItem *cloudmodel.VMPodNodeConnection) (diffBase *diffbase.VMPodNodeConnection, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *VMPodNodeConnection) generateDBItemToAdd(cloudItem *cloudmodel.VMPodNodeConnection) (*mysql.VMPodNodeConnection, bool) {
	vmID, exists := c.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.VMPodNodeConnection{
		Domain:    c.cache.DomainLcuuid,
		SubDomain: cloudItem.SubDomainLcuuid,
		VMID:      vmID,
		PodNodeID: c.cache.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (c *VMPodNodeConnection) generateUpdateInfo(diffBase *diffbase.VMPodNodeConnection, cloudItem *cloudmodel.VMPodNodeConnection) (map[string]interface{}, bool) {
	return nil, false
}
