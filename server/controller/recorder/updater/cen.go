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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type CEN struct {
	UpdaterBase[
		cloudmodel.CEN,
		mysql.CEN,
		*diffbase.CEN,
		*message.CENAdd,
		message.CENAdd,
		*message.CENUpdate,
		message.CENUpdate,
		*message.CENFieldsUpdate,
		message.CENFieldsUpdate,
		*message.CENDelete,
		message.CENDelete]
}

func NewCEN(wholeCache *cache.Cache, cloudData []cloudmodel.CEN) *CEN {
	updater := &CEN{
		newUpdaterBase[
			cloudmodel.CEN,
			mysql.CEN,
			*diffbase.CEN,
			*message.CENAdd,
			message.CENAdd,
			*message.CENUpdate,
			message.CENUpdate,
			*message.CENFieldsUpdate,
			message.CENFieldsUpdate,
			*message.CENDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_CEN_EN,
			wholeCache,
			db.NewCEN(),
			wholeCache.DiffBaseDataSet.CENs,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *CEN) getDiffBaseByCloudItem(cloudItem *cloudmodel.CEN) (diffBase *diffbase.CEN, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *CEN) generateDBItemToAdd(cloudItem *cloudmodel.CEN) (*mysql.CEN, bool) {
	vpcIDs := []int{}
	for _, vpcLcuuid := range cloudItem.VPCLcuuids {
		vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(vpcLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
				ctrlrcommon.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
			))
			continue
		}
		vpcIDs = append(vpcIDs, vpcID)
	}
	dbItem := &mysql.CEN{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Domain: c.cache.DomainLcuuid,
		VPCIDs: rcommon.IntSliceToString(vpcIDs),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *CEN) generateUpdateInfo(diffBase *diffbase.CEN, cloudItem *cloudmodel.CEN) (*message.CENFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.CENFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if !rcommon.ElementsSame(diffBase.VPCLcuuids, cloudItem.VPCLcuuids) {
		vpcIDs := []int{}
		for _, vpcLcuuid := range cloudItem.VPCLcuuids {
			vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(vpcLcuuid)
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
					ctrlrcommon.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
				))
				continue
			}
			vpcIDs = append(vpcIDs, vpcID)
		}
		mapInfo["epc_ids"] = rcommon.IntSliceToString(vpcIDs)
		structInfo.VPCIDs.SetNew(vpcIDs)
		structInfo.VPCLcuuids.Set(diffBase.VPCLcuuids, cloudItem.VPCLcuuids)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
