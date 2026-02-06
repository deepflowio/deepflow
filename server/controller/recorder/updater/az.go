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

// AZMessageFactory AZ资源的消息工厂
type AZMessageFactory struct{}

func (f *AZMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedAZs{}
}

func (f *AZMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedAZ{}
}

func (f *AZMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedAZs{}
}

func (f *AZMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedAZFields{}
}

type AZ struct {
	UpdaterBase[
		cloudmodel.AZ,
		*diffbase.AZ,
		*metadbmodel.AZ,
		metadbmodel.AZ,
	]
}

func NewAZ(wholeCache *cache.Cache, cloudData []cloudmodel.AZ) *AZ {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_AZ_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_AZ_EN, &AZMessageFactory{})
	}

	updater := &AZ{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_AZ_EN,
			wholeCache,
			db.NewAZ().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.AZs,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (z *AZ) generateDBItemToAdd(cloudItem *cloudmodel.AZ) (*metadbmodel.AZ, bool) {
	dbItem := &metadbmodel.AZ{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Region: cloudItem.RegionLcuuid,
		Domain: z.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (z *AZ) generateUpdateInfo(diffBase *diffbase.AZ, cloudItem *cloudmodel.AZ) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedAZFields{}
	mapInfo := make(map[string]interface{})
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
