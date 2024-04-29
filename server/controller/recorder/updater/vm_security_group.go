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

type VMSecurityGroup struct {
	UpdaterBase[
		cloudmodel.VMSecurityGroup,
		mysql.VMSecurityGroup,
		*diffbase.VMSecurityGroup,
		*message.VMSecurityGroupAdd,
		message.VMSecurityGroupAdd,
		*message.VMSecurityGroupUpdate,
		message.VMSecurityGroupUpdate,
		*message.VMSecurityGroupFieldsUpdate,
		message.VMSecurityGroupFieldsUpdate,
		*message.VMSecurityGroupDelete,
		message.VMSecurityGroupDelete]
}

func NewVMSecurityGroup(wholeCache *cache.Cache, cloudData []cloudmodel.VMSecurityGroup) *VMSecurityGroup {
	updater := &VMSecurityGroup{
		newUpdaterBase[
			cloudmodel.VMSecurityGroup,
			mysql.VMSecurityGroup,
			*diffbase.VMSecurityGroup,
			*message.VMSecurityGroupAdd,
			message.VMSecurityGroupAdd,
			*message.VMSecurityGroupUpdate,
			message.VMSecurityGroupUpdate,
			*message.VMSecurityGroupFieldsUpdate,
			message.VMSecurityGroupFieldsUpdate,
			*message.VMSecurityGroupDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN,
			wholeCache,
			db.NewVMSecurityGroup().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.VMSecurityGroups,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (z *VMSecurityGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.VMSecurityGroup) (diffBase *diffbase.VMSecurityGroup, exists bool) {
	diffBase, exists = z.diffBaseData[cloudItem.Lcuuid]
	return
}

func (v *VMSecurityGroup) generateDBItemToAdd(cloudItem *cloudmodel.VMSecurityGroup) (*mysql.VMSecurityGroup, bool) {
	securityGroupID, exists := v.cache.ToolDataSet.GetSecurityGroupIDByLcuuid(cloudItem.SecurityGroupLcuuid)
	if !exists {
		log.Error(v.metadata.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.SecurityGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}
	vmID, exists := v.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.VMLcuuid)
	if !exists {
		log.Error(v.metadata.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.VMLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}

	dbItem := &mysql.VMSecurityGroup{
		VMID:            vmID,
		SecurityGroupID: securityGroupID,
		Priority:        cloudItem.Priority,
		Domain:          v.metadata.Domain.Lcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (v *VMSecurityGroup) generateUpdateInfo(diffBase *diffbase.VMSecurityGroup, cloudItem *cloudmodel.VMSecurityGroup) (*message.VMSecurityGroupFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VMSecurityGroupFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Priority != cloudItem.Priority {
		mapInfo["priority"] = cloudItem.Priority
		structInfo.Priority.Set(diffBase.Priority, cloudItem.Priority)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
