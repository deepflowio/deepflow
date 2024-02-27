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

type NATVMConnection struct {
	UpdaterBase[
		cloudmodel.NATVMConnection,
		mysql.NATVMConnection,
		*diffbase.NATVMConnection,
		*message.NATVMConnectionAdd,
		message.NATVMConnectionAdd,
		*message.NATVMConnectionUpdate,
		message.NATVMConnectionUpdate,
		*message.NATVMConnectionFieldsUpdate,
		message.NATVMConnectionFieldsUpdate,
		*message.NATVMConnectionDelete,
		message.NATVMConnectionDelete]
}

func NewNATVMConnection(wholeCache *cache.Cache, cloudData []cloudmodel.NATVMConnection) *NATVMConnection {
	updater := &NATVMConnection{
		newUpdaterBase[
			cloudmodel.NATVMConnection,
			mysql.NATVMConnection,
			*diffbase.NATVMConnection,
			*message.NATVMConnectionAdd,
			message.NATVMConnectionAdd,
			*message.NATVMConnectionUpdate,
			message.NATVMConnectionUpdate,
			*message.NATVMConnectionFieldsUpdate,
			message.NATVMConnectionFieldsUpdate,
			*message.NATVMConnectionDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN,
			wholeCache,
			db.NewNATVMConnection(),
			wholeCache.DiffBaseDataSet.NATVMConnections,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *NATVMConnection) getDiffBaseByCloudItem(cloudItem *cloudmodel.NATVMConnection) (diffBase *diffbase.NATVMConnection, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *NATVMConnection) generateDBItemToAdd(cloudItem *cloudmodel.NATVMConnection) (*mysql.NATVMConnection, bool) {
	vmID, exists := c.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	natID, exists := c.cache.ToolDataSet.GetNATGatewayIDByLcuuid(cloudItem.NATGatewayLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, cloudItem.NATGatewayLcuuid,
			ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.NATVMConnection{
		Domain:       c.cache.DomainLcuuid,
		VMID:         vmID,
		NATGatewayID: natID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (c *NATVMConnection) generateUpdateInfo(diffBase *diffbase.NATVMConnection, cloudItem *cloudmodel.NATVMConnection) (*message.NATVMConnectionFieldsUpdate, map[string]interface{}, bool) {
	return nil, nil, false
}
