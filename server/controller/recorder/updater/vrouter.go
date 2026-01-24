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
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// VRouterMessageFactory VRouter资源的消息工厂
type VRouterMessageFactory struct{}

func (f *VRouterMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedVRouters{}
}

func (f *VRouterMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedVRouter{}
}

func (f *VRouterMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedVRouters{}
}

func (f *VRouterMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedVRouterFields{}
}

type VRouter struct {
	UpdaterBase[
		cloudmodel.VRouter,
		*diffbase.VRouter,
		*metadbmodel.VRouter,
		metadbmodel.VRouter,
	]
}

func NewVRouter(wholeCache *cache.Cache, cloudData []cloudmodel.VRouter) *VRouter {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, &VRouterMessageFactory{})
	}

	updater := &VRouter{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN,
			wholeCache,
			db.NewVRouter().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.VRouters,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

func (r *VRouter) generateDBItemToAdd(cloudItem *cloudmodel.VRouter) (*metadbmodel.VRouter, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
		), r.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.VRouter{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		State:          rcommon.VROUTER_STATE_RUNNING,
		GWLaunchServer: cloudItem.GWLaunchServer,
		Domain:         r.metadata.GetDomainLcuuid(),
		Region:         cloudItem.RegionLcuuid,
		VPCID:          vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *VRouter) generateUpdateInfo(diffBase *diffbase.VRouter, cloudItem *cloudmodel.VRouter) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedVRouterFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
			), r.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID)
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
