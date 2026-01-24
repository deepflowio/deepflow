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

// SubnetMessageFactory Subnet资源的消息工厂
type SubnetMessageFactory struct{}

func (f *SubnetMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedSubnets{}
}

func (f *SubnetMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedSubnet{}
}

func (f *SubnetMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedSubnets{}
}

func (f *SubnetMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedSubnetFields{}
}

type Subnet struct {
	UpdaterBase[
		cloudmodel.Subnet,
		*diffbase.Subnet,
		*metadbmodel.Subnet,
		metadbmodel.Subnet,
	]
}

func NewSubnet(wholeCache *cache.Cache, cloudData []cloudmodel.Subnet) *Subnet {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, &SubnetMessageFactory{})
	}

	updater := &Subnet{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_SUBNET_EN,
			wholeCache,
			db.NewSubnet().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.Subnets,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (s *Subnet) generateDBItemToAdd(cloudItem *cloudmodel.Subnet) (*metadbmodel.Subnet, bool) {
	networkID, exists := s.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
		return nil, false
	}
	prefix, netmask, err := rcommon.CIDRToPreNetMask(cloudItem.CIDR)
	if err != nil {
		log.Errorf("convert %s cidr: %s failed: %v", ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.CIDR, err.Error(), s.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.Subnet{
		Name:      cloudItem.Name,
		Label:     cloudItem.Label,
		Prefix:    prefix,
		Netmask:   netmask,
		SubDomain: cloudItem.SubDomainLcuuid,
		NetworkID: networkID,
		Domain:    s.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *Subnet) generateUpdateInfo(diffBase *diffbase.Subnet, cloudItem *cloudmodel.Subnet) (types.UpdatedFields, map[string]interface{}, bool) {
	// 创建具体的UpdatedSubnetFields，然后转换为接口类型
	structInfo := &message.UpdatedSubnetFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}

	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
