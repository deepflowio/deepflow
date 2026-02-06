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

// VMPodNodeConnectionMessageFactory VMPodNodeConnection资源的消息工厂
type VMPodNodeConnectionMessageFactory struct{}

func (f *VMPodNodeConnectionMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedVMPodNodeConnections{}
}

func (f *VMPodNodeConnectionMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedVMPodNodeConnection{}
}

func (f *VMPodNodeConnectionMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedVMPodNodeConnections{}
}

func (f *VMPodNodeConnectionMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedVMPodNodeConnectionFields{}
}

type VMPodNodeConnection struct {
	UpdaterBase[
		cloudmodel.VMPodNodeConnection,
		*diffbase.VMPodNodeConnection,
		*metadbmodel.VMPodNodeConnection,
		metadbmodel.VMPodNodeConnection,
	]
}

func NewVMPodNodeConnection(wholeCache *cache.Cache, cloudData []cloudmodel.VMPodNodeConnection) *VMPodNodeConnection {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, &VMPodNodeConnectionMessageFactory{})
	}

	updater := &VMPodNodeConnection{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN,
			wholeCache,
			db.NewVMPodNodeConnection().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.VMPodNodeConnections,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

func (c *VMPodNodeConnection) generateDBItemToAdd(cloudItem *cloudmodel.VMPodNodeConnection) (*metadbmodel.VMPodNodeConnection, bool) {
	vmID, exists := c.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.VMPodNodeConnection{
		Domain:    c.metadata.GetDomainLcuuid(),
		SubDomain: cloudItem.SubDomainLcuuid,
		VMID:      vmID,
		PodNodeID: c.cache.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *VMPodNodeConnection) generateUpdateInfo(diffBase *diffbase.VMPodNodeConnection, cloudItem *cloudmodel.VMPodNodeConnection) (types.UpdatedFields, map[string]interface{}, bool) {
	return nil, nil, false
}
