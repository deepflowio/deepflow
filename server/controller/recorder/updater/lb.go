/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type LB struct {
	UpdaterBase[cloudmodel.LB, mysql.LB, *cache.LB]
}

func NewLB(wholeCache *cache.Cache, cloudData []cloudmodel.LB) *LB {
	updater := &LB{
		UpdaterBase[cloudmodel.LB, mysql.LB, *cache.LB]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_LB_EN,
			cache:        wholeCache,
			dbOperator:   db.NewLB(),
			diffBaseData: wholeCache.LBs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (l *LB) getDiffBaseByCloudItem(cloudItem *cloudmodel.LB) (diffBase *cache.LB, exists bool) {
	diffBase, exists = l.diffBaseData[cloudItem.Lcuuid]
	return
}

func (l *LB) generateDBItemToAdd(cloudItem *cloudmodel.LB) (*mysql.LB, bool) {
	vpcID, exists := l.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.LB{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		UID:    cloudItem.Label,
		Model:  cloudItem.Model,
		VIP:    cloudItem.VIP,
		Domain: l.cache.DomainLcuuid,
		Region: cloudItem.RegionLcuuid,
		VPCID:  vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (l *LB) generateUpdateInfo(diffBase *cache.LB, cloudItem *cloudmodel.LB) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Model != cloudItem.Model {
		updateInfo["model"] = cloudItem.Model
	}
	if diffBase.VIP != cloudItem.VIP {
		updateInfo["vip"] = cloudItem.VIP
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
