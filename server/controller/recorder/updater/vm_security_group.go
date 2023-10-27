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

type VMSecurityGroup struct {
	UpdaterBase[cloudmodel.VMSecurityGroup, mysql.VMSecurityGroup, *cache.VMSecurityGroup]
}

func NewVMSecurityGroup(wholeCache *cache.Cache, cloudData []cloudmodel.VMSecurityGroup) *VMSecurityGroup {
	updater := &VMSecurityGroup{
		UpdaterBase[cloudmodel.VMSecurityGroup, mysql.VMSecurityGroup, *cache.VMSecurityGroup]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN,
			cache:        wholeCache,
			dbOperator:   db.NewVMSecurityGroup(),
			diffBaseData: wholeCache.VMSecurityGroups,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (z *VMSecurityGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.VMSecurityGroup) (diffBase *cache.VMSecurityGroup, exists bool) {
	diffBase, exists = z.diffBaseData[cloudItem.Lcuuid]
	return
}

func (v *VMSecurityGroup) generateDBItemToAdd(cloudItem *cloudmodel.VMSecurityGroup) (*mysql.VMSecurityGroup, bool) {
	securityGroupID, exists := v.cache.ToolDataSet.GetSecurityGroupIDByLcuuid(cloudItem.SecurityGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.SecurityGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	vmID, exists := v.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.VMSecurityGroup{
		VMID:            vmID,
		SecurityGroupID: securityGroupID,
		Priority:        cloudItem.Priority,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (v *VMSecurityGroup) generateUpdateInfo(diffBase *cache.VMSecurityGroup, cloudItem *cloudmodel.VMSecurityGroup) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Priority != cloudItem.Priority {
		updateInfo["priority"] = cloudItem.Priority
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
