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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// LBVMConnectionMessageFactory LBVMConnection资源的消息工厂
type LBVMConnectionMessageFactory struct{}

func (f *LBVMConnectionMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedLBVMConnections{}
}

func (f *LBVMConnectionMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedLBVMConnection{}
}

func (f *LBVMConnectionMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedLBVMConnections{}
}

func (f *LBVMConnectionMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedLBVMConnectionFields{}
}

type LBVMConnection struct {
	UpdaterBase[
		cloudmodel.LBVMConnection,
		*diffbase.LBVMConnection,
		*metadbmodel.LBVMConnection,
		metadbmodel.LBVMConnection,
	]
}

func NewLBVMConnection(wholeCache *cache.Cache, cloudData []cloudmodel.LBVMConnection) *LBVMConnection {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN, &LBVMConnectionMessageFactory{})
	}

	updater := &LBVMConnection{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN,
			wholeCache,
			db.NewLBVMConnection().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.LBVMConnections,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (c *LBVMConnection) generateDBItemToAdd(cloudItem *cloudmodel.LBVMConnection) (*metadbmodel.LBVMConnection, bool) {
	vmID, exists := c.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}
	lbID, exists := c.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.LBVMConnection{
		Domain: c.metadata.GetDomainLcuuid(),
		VMID:   vmID,
		LBID:   lbID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (l *LBVMConnection) generateUpdateInfo(diffBase *diffbase.LBVMConnection, cloudItem *cloudmodel.LBVMConnection) (types.UpdatedFields, map[string]interface{}, bool) {
	return nil, nil, false
}
