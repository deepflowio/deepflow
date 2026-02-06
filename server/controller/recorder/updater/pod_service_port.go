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

// PodServicePortMessageFactory defines the message factory for PodServicePort
type PodServicePortMessageFactory struct{}

func (f *PodServicePortMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodServicePorts{}
}

func (f *PodServicePortMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodServicePort{}
}

func (f *PodServicePortMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodServicePorts{}
}

func (f *PodServicePortMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodServicePortFields{}
}

type PodServicePort struct {
	UpdaterBase[
		cloudmodel.PodServicePort,
		*diffbase.PodServicePort,
		*metadbmodel.PodServicePort,
		metadbmodel.PodServicePort,
	]
}

func NewPodServicePort(wholeCache *cache.Cache, cloudData []cloudmodel.PodServicePort) *PodServicePort {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, &PodServicePortMessageFactory{})
	}

	updater := &PodServicePort{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN,
			wholeCache,
			db.NewPodServicePort().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodServicePorts,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// Implement DataGenerator interface

func (p *PodServicePort) generateDBItemToAdd(cloudItem *cloudmodel.PodServicePort) (*metadbmodel.PodServicePort, bool) {
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodServicePort{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Port:         cloudItem.Port,
		TargetPort:   cloudItem.TargetPort,
		NodePort:     cloudItem.NodePort,
		PodServiceID: podServiceID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       p.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodServicePort) generateUpdateInfo(diffBase *diffbase.PodServicePort, cloudItem *cloudmodel.PodServicePort) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedPodServicePortFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	// Note: diffbase.PodServicePort only has Name and SubDomainLcuuid fields
	// Port, TargetPort, NodePort are not part of the diffbase structure

	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
