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
)

type CEN struct {
	UpdaterBase[cloudmodel.CEN, mysql.CEN, *diffbase.CEN]
}

func NewCEN(wholeCache *cache.Cache, cloudData []cloudmodel.CEN) *CEN {
	updater := &CEN{
		UpdaterBase[cloudmodel.CEN, mysql.CEN, *diffbase.CEN]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_CEN_EN,
			cache:        wholeCache,
			dbOperator:   db.NewCEN(),
			diffBaseData: wholeCache.DiffBaseDataSet.CENs,
			cloudData:    cloudData,
		},
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

func (c *CEN) generateUpdateInfo(diffBase *diffbase.CEN, cloudItem *cloudmodel.CEN) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
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
		updateInfo["epc_ids"] = rcommon.IntSliceToString(vpcIDs)
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
