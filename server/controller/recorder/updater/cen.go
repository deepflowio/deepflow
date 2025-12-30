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
)

type CEN struct {
	UpdaterBase[
		cloudmodel.CEN,
		*diffbase.CEN,
		*metadbmodel.CEN,
		metadbmodel.CEN,
		*message.AddedCENs,
		message.AddedCENs,
		message.AddNoneAddition,
		*message.UpdatedCEN,
		message.UpdatedCEN,
		*message.UpdatedCENFields,
		message.UpdatedCENFields,
		*message.DeletedCENs,
		message.DeletedCENs,
		message.DeleteNoneAddition]
}

func NewCEN(wholeCache *cache.Cache, cloudData []cloudmodel.CEN) *CEN {
	updater := &CEN{
		newUpdaterBase[
			cloudmodel.CEN,
			*diffbase.CEN,
			*metadbmodel.CEN,
			metadbmodel.CEN,
			*message.AddedCENs,
			message.AddedCENs,
			message.AddNoneAddition,
			*message.UpdatedCEN,
			message.UpdatedCEN,
			*message.UpdatedCENFields,
			message.UpdatedCENFields,
			*message.DeletedCENs,
			message.DeletedCENs,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_CEN_EN,
			wholeCache,
			db.NewCEN().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.CENs,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *CEN) generateDBItemToAdd(cloudItem *cloudmodel.CEN) (*metadbmodel.CEN, bool) {
	vpcIDs := []int{}
	for _, vpcLcuuid := range cloudItem.VPCLcuuids {
		vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(vpcLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
				ctrlrcommon.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
			), c.metadata.LogPrefixes)
			continue
		}
		vpcIDs = append(vpcIDs, vpcID)
	}
	dbItem := &metadbmodel.CEN{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Domain: c.metadata.GetDomainLcuuid(),
		VPCIDs: vpcIDs,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *CEN) generateUpdateInfo(diffBase *diffbase.CEN, cloudItem *cloudmodel.CEN) (*message.UpdatedCENFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedCENFields)
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
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_VPC_EN, vpcLcuuid,
					ctrlrcommon.RESOURCE_TYPE_CEN_EN, cloudItem.Lcuuid,
				), c.metadata.LogPrefixes)
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
