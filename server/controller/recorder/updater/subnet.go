/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type Subnet struct {
	UpdaterBase[cloudmodel.Subnet, mysql.Subnet, *cache.Subnet]
}

func NewSubnet(wholeCache *cache.Cache, cloudData []cloudmodel.Subnet) *Subnet {
	updater := &Subnet{
		UpdaterBase[cloudmodel.Subnet, mysql.Subnet, *cache.Subnet]{
			cache:        wholeCache,
			dbOperator:   db.NewSubnet(),
			diffBaseData: wholeCache.Subnets,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (s *Subnet) getDiffBaseByCloudItem(cloudItem *cloudmodel.Subnet) (diffBase *cache.Subnet, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *Subnet) generateDBItemToAdd(cloudItem *cloudmodel.Subnet) (*mysql.Subnet, bool) {
	networkID, exists := s.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
			common.RESOURCE_TYPE_SUBNET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	prefix, netmask, err := common.CIDRToPreNetMask(cloudItem.CIDR)
	if err != nil {
		log.Errorf("convert %s cidr: %s failed: %v", common.RESOURCE_TYPE_SUBNET_EN, cloudItem.CIDR, err)
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

func (s *Subnet) generateUpdateInfo(diffBase *cache.Subnet, cloudItem *cloudmodel.Subnet) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (s *Subnet) addCache(dbItems []*mysql.Subnet) {
	s.cache.AddSubnets(dbItems)
}

func (s *Subnet) updateCache(cloudItem *cloudmodel.Subnet, diffBase *cache.Subnet) {
	diffBase.Update(cloudItem)
}

func (s *Subnet) deleteCache(lcuuids []string) {
	s.cache.DeleteSubnets(lcuuids)
}
