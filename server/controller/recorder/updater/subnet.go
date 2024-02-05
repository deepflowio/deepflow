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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type Subnet struct {
	UpdaterBase[
		cloudmodel.Subnet,
		mysql.Subnet,
		*diffbase.Subnet, *message.SubnetAdd, message.SubnetAdd, *message.SubnetUpdate, message.SubnetUpdate, *message.SubnetFieldsUpdate, message.SubnetFieldsUpdate, *message.SubnetDelete, message.SubnetDelete]
}

func NewSubnet(wholeCache *cache.Cache, cloudData []cloudmodel.Subnet) *Subnet {
	updater := &Subnet{
		newUpdaterBase[
			cloudmodel.Subnet,
			mysql.Subnet,
			*diffbase.Subnet, *message.SubnetAdd, message.SubnetAdd, *message.SubnetUpdate, message.SubnetUpdate, *message.SubnetFieldsUpdate, message.SubnetFieldsUpdate, *message.SubnetDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_SUBNET_EN,
			wholeCache,
			db.NewSubnet(),
			wholeCache.DiffBaseDataSet.Subnets,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (s *Subnet) getDiffBaseByCloudItem(cloudItem *cloudmodel.Subnet) (diffBase *diffbase.Subnet, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *Subnet) generateDBItemToAdd(cloudItem *cloudmodel.Subnet) (*mysql.Subnet, bool) {
	networkID, exists := s.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	prefix, netmask, err := rcommon.CIDRToPreNetMask(cloudItem.CIDR)
	if err != nil {
		log.Errorf("convert %s cidr: %s failed: %v", ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, cloudItem.CIDR, err)
		return nil, false
	}

	dbItem := &mysql.Subnet{
		Name:      cloudItem.Name,
		Label:     cloudItem.Label,
		Prefix:    prefix,
		Netmask:   netmask,
		SubDomain: cloudItem.SubDomainLcuuid,
		NetworkID: networkID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *Subnet) generateUpdateInfo(diffBase *diffbase.Subnet, cloudItem *cloudmodel.Subnet) (*message.SubnetFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.SubnetFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
