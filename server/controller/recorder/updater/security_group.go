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

type SecurityGroup struct {
	UpdaterBase[cloudmodel.SecurityGroup, mysql.SecurityGroup, *cache.SecurityGroup]
}

func NewSecurityGroup(wholeCache *cache.Cache, cloudData []cloudmodel.SecurityGroup) *SecurityGroup {
	updater := &SecurityGroup{
		UpdaterBase[cloudmodel.SecurityGroup, mysql.SecurityGroup, *cache.SecurityGroup]{
			cache:        wholeCache,
			dbOperator:   db.NewSecurityGroup(),
			diffBaseData: wholeCache.SecurityGroups,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (g *SecurityGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.SecurityGroup) (diffBase *cache.SecurityGroup, exists bool) {
	diffBase, exists = g.diffBaseData[cloudItem.Lcuuid]
	return
}

func (g *SecurityGroup) generateDBItemToAdd(cloudItem *cloudmodel.SecurityGroup) (*mysql.SecurityGroup, bool) {
	dbItem := &mysql.SecurityGroup{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Domain: g.cache.DomainLcuuid,
		Region: cloudItem.RegionLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if cloudItem.VPCLcuuid != "" {
		vpcID, exists := g.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				common.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		dbItem.VPCID = vpcID
	}
	return dbItem, true
}

func (g *SecurityGroup) generateUpdateInfo(diffBase *cache.SecurityGroup, cloudItem *cloudmodel.SecurityGroup) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (g *SecurityGroup) addCache(dbItems []*mysql.SecurityGroup) {
	g.cache.AddSecurityGroups(dbItems)
}

func (g *SecurityGroup) updateCache(cloudItem *cloudmodel.SecurityGroup, diffBase *cache.SecurityGroup) {
	diffBase.Update(cloudItem)
}

func (g *SecurityGroup) deleteCache(lcuuids []string) {
	g.cache.DeleteSecurityGroups(lcuuids)
}
