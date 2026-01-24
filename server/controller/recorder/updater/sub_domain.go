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

// SubDomainMessageFactory SubDomain资源的消息工厂
type SubDomainMessageFactory struct{}

func (f *SubDomainMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedSubDomains{}
}

func (f *SubDomainMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedSubDomain{}
}

func (f *SubDomainMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedSubDomains{}
}

func (f *SubDomainMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedSubDomainFields{}
}

type SubDomain struct {
	UpdaterBase[
		cloudmodel.SubDomain,
		*diffbase.SubDomain,
		*metadbmodel.SubDomain,
		metadbmodel.SubDomain,
	]
}

func NewSubDomain(wholeCache *cache.Cache, cloudData []cloudmodel.SubDomain) *SubDomain {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, &SubDomainMessageFactory{})
	}

	updater := &SubDomain{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN,
			wholeCache,
			db.NewSubDomain().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.SubDomains,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

func (d *SubDomain) generateDBItemToAdd(cloudItem *cloudmodel.SubDomain) (*metadbmodel.SubDomain, bool) {
	dbItem := &metadbmodel.SubDomain{
		TeamID:      cloudItem.TeamID,
		Name:        cloudItem.Name,
		DisplayName: cloudItem.DisplayName,
		ClusterID:   cloudItem.ClusterID,
		Config:      cloudItem.Config,
		Domain:      d.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (d *SubDomain) generateUpdateInfo(diffBase *diffbase.SubDomain, cloudItem *cloudmodel.SubDomain) (types.UpdatedFields, map[string]interface{}, bool) {
	// 创建具体的UpdatedSubDomainFields，然后转换为接口类型
	structInfo := &message.UpdatedSubDomainFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
