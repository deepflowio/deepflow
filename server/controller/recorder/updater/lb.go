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

// LBMessageFactory LB资源的消息工厂
type LBMessageFactory struct{}

func (f *LBMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedLBs{}
}

func (f *LBMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedLB{}
}

func (f *LBMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedLBs{}
}

func (f *LBMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedLBFields{}
}

type LB struct {
	UpdaterBase[
		cloudmodel.LB,
		*diffbase.LB,
		*metadbmodel.LB,
		metadbmodel.LB,
	]
}

func NewLB(wholeCache *cache.Cache, cloudData []cloudmodel.LB) *LB {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_LB_EN, &LBMessageFactory{})
	}

	updater := &LB{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_LB_EN,
			wholeCache,
			db.NewLB().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.LBs,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (l *LB) generateDBItemToAdd(cloudItem *cloudmodel.LB) (*metadbmodel.LB, bool) {
	vpcID, exists := l.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.Lcuuid,
		), l.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.LB{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		UID:    cloudItem.Label,
		Model:  cloudItem.Model,
		VIP:    cloudItem.VIP,
		Domain: l.metadata.GetDomainLcuuid(),
		Region: cloudItem.RegionLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (l *LB) generateUpdateInfo(diffBase *diffbase.LB, cloudItem *cloudmodel.LB) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedLBFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Model != cloudItem.Model {
		mapInfo["model"] = cloudItem.Model
		structInfo.Model.Set(diffBase.Model, cloudItem.Model)
	}
	if diffBase.VIP != cloudItem.VIP {
		mapInfo["vip"] = cloudItem.VIP
		structInfo.VIP.Set(diffBase.VIP, cloudItem.VIP)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
