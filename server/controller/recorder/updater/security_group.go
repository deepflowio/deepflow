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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type SecurityGroup struct {
	UpdaterBase[
		cloudmodel.SecurityGroup,
		mysql.SecurityGroup,
		*diffbase.SecurityGroup, *message.SecurityGroupAdd, message.SecurityGroupAdd, *message.SecurityGroupUpdate, message.SecurityGroupUpdate, *message.SecurityGroupFieldsUpdate, message.SecurityGroupFieldsUpdate, *message.SecurityGroupDelete, message.SecurityGroupDelete]
}

func NewSecurityGroup(wholeCache *cache.Cache, cloudData []cloudmodel.SecurityGroup) *SecurityGroup {
	updater := &SecurityGroup{
		newUpdaterBase[
			cloudmodel.SecurityGroup,
			mysql.SecurityGroup,
			*diffbase.SecurityGroup, *message.SecurityGroupAdd, message.SecurityGroupAdd, *message.SecurityGroupUpdate, message.SecurityGroupUpdate, *message.SecurityGroupFieldsUpdate, message.SecurityGroupFieldsUpdate, *message.SecurityGroupDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN,
			wholeCache,
			db.NewSecurityGroup(),
			wholeCache.DiffBaseDataSet.SecurityGroups,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (g *SecurityGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.SecurityGroup) (diffBase *diffbase.SecurityGroup, exists bool) {
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
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		dbItem.VPCID = vpcID
	}
	return dbItem, true
}

func (g *SecurityGroup) generateUpdateInfo(diffBase *diffbase.SecurityGroup, cloudItem *cloudmodel.SecurityGroup) (*message.SecurityGroupFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.SecurityGroupFieldsUpdate)
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
