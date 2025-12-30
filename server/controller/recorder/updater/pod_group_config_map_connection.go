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

type PodGroupConfigMapConnection struct {
	UpdaterBase[
		cloudmodel.PodGroupConfigMapConnection,
		*diffbase.PodGroupConfigMapConnection,
		*metadbmodel.PodGroupConfigMapConnection,
		metadbmodel.PodGroupConfigMapConnection,
		*message.AddedPodGroupConfigMapConnections,
		message.AddedPodGroupConfigMapConnections,
		message.AddNoneAddition,
		*message.UpdatedPodGroupConfigMapConnection,
		message.UpdatedPodGroupConfigMapConnection,
		*message.UpdatedPodGroupConfigMapConnectionFields,
		message.UpdatedPodGroupConfigMapConnectionFields,
		*message.DeletedPodGroupConfigMapConnections,
		message.DeletedPodGroupConfigMapConnections,
		message.DeleteNoneAddition]
}

func NewPodGroupConfigMapConnection(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroupConfigMapConnection) *PodGroupConfigMapConnection {
	updater := &PodGroupConfigMapConnection{
		newUpdaterBase[
			cloudmodel.PodGroupConfigMapConnection,
			*diffbase.PodGroupConfigMapConnection,
			*metadbmodel.PodGroupConfigMapConnection,
			metadbmodel.PodGroupConfigMapConnection,
			*message.AddedPodGroupConfigMapConnections,
			message.AddedPodGroupConfigMapConnections,
			message.AddNoneAddition,
			*message.UpdatedPodGroupConfigMapConnection,
			message.UpdatedPodGroupConfigMapConnection,
			*message.UpdatedPodGroupConfigMapConnectionFields,
			message.UpdatedPodGroupConfigMapConnectionFields,
			*message.DeletedPodGroupConfigMapConnections,
			message.DeletedPodGroupConfigMapConnections,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN,
			wholeCache,
			db.NewPodGroupConfigMapConnection().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodGroupConfigMapConnections,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (h *PodGroupConfigMapConnection) generateDBItemToAdd(cloudItem *cloudmodel.PodGroupConfigMapConnection) (*metadbmodel.PodGroupConfigMapConnection, bool) {
	podGroupID, exists := h.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN, cloudItem.Lcuuid,
		), h.metadata.LogPrefixes)
		return nil, false
	}
	configMapID, exists := h.cache.ToolDataSet.GetConfigMapIDByLcuuid(cloudItem.ConfigMapLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, cloudItem.ConfigMapLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN, cloudItem.Lcuuid,
		), h.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodGroupConfigMapConnection{
		PodGroupID:  podGroupID,
		ConfigMapID: configMapID,
		Domain:      h.metadata.GetDomainLcuuid(),
		SubDomain:   h.metadata.GetSubDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (h *PodGroupConfigMapConnection) generateUpdateInfo(diffBase *diffbase.PodGroupConfigMapConnection, cloudItem *cloudmodel.PodGroupConfigMapConnection) (*message.UpdatedPodGroupConfigMapConnectionFields, map[string]interface{}, bool) {
	return nil, nil, false
}
