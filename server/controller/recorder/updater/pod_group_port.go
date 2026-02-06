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

// PodGroupPortMessageFactory defines the message factory for PodGroupPort
type PodGroupPortMessageFactory struct{}

func (f *PodGroupPortMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodGroupPorts{}
}

func (f *PodGroupPortMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodGroupPort{}
}

func (f *PodGroupPortMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodGroupPorts{}
}

func (f *PodGroupPortMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodGroupPortFields{}
}

type PodGroupPort struct {
	UpdaterBase[
		cloudmodel.PodGroupPort,
		*diffbase.PodGroupPort,
		*metadbmodel.PodGroupPort,
		metadbmodel.PodGroupPort,
	]
}

func NewPodGroupPort(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroupPort) *PodGroupPort {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, &PodGroupPortMessageFactory{})
	}

	updater := &PodGroupPort{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN,
			wholeCache,
			db.NewPodGroupPort().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodGroupPorts,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// Implement DataGenerator interface

func (p *PodGroupPort) generateDBItemToAdd(cloudItem *cloudmodel.PodGroupPort) (*metadbmodel.PodGroupPort, bool) {
	podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodGroupPort{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Port:         cloudItem.Port,
		PodServiceID: podServiceID,
		PodGroupID:   podGroupID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       p.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodGroupPort) generateUpdateInfo(diffBase *diffbase.PodGroupPort, cloudItem *cloudmodel.PodGroupPort) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedPodGroupPortFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}

	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
