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
)

type PeerConnection struct {
	UpdaterBase[
		cloudmodel.PeerConnection,
		*diffbase.PeerConnection,
		*metadbmodel.PeerConnection,
		metadbmodel.PeerConnection,
		*message.AddedPeerConnections,
		message.AddedPeerConnections,
		message.AddNoneAddition,
		*message.UpdatedPeerConnection,
		message.UpdatedPeerConnection,
		*message.UpdatedPeerConnectionFields,
		message.UpdatedPeerConnectionFields,
		*message.DeletedPeerConnections,
		message.DeletedPeerConnections,
		message.DeleteNoneAddition]
}

func NewPeerConnection(wholeCache *cache.Cache, cloudData []cloudmodel.PeerConnection) *PeerConnection {
	updater := &PeerConnection{
		newUpdaterBase[
			cloudmodel.PeerConnection,
			*diffbase.PeerConnection,
			*metadbmodel.PeerConnection,
			metadbmodel.PeerConnection,
			*message.AddedPeerConnections,
			message.AddedPeerConnections,
			message.AddNoneAddition,
			*message.UpdatedPeerConnection,
			message.UpdatedPeerConnection,
			*message.UpdatedPeerConnectionFields,
			message.UpdatedPeerConnectionFields,
			*message.DeletedPeerConnections,
			message.DeletedPeerConnections,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN,
			wholeCache,
			db.NewPeerConnection().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PeerConnections,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *PeerConnection) generateDBItemToAdd(cloudItem *cloudmodel.PeerConnection) (*metadbmodel.PeerConnection, bool) {
	remoteVPCID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.RemoteVPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.RemoteVPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}
	localVPCID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.LocalVPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.LocalVPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.PeerConnection{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		TeamID:       c.msgMetadata.GetTeamID(),
		Domain:       c.metadata.GetDomainLcuuid(),
		RemoteVPCID:  &remoteVPCID,
		LocalVPCID:   &localVPCID,
		RemoteDomain: c.metadata.GetDomainLcuuid(),
		LocalDomain:  c.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *PeerConnection) generateUpdateInfo(diffBase *diffbase.PeerConnection, cloudItem *cloudmodel.PeerConnection) (*message.UpdatedPeerConnectionFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPeerConnectionFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
