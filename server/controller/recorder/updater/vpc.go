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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type VPC struct {
	UpdaterBase[cloudmodel.VPC, mysql.VPC, *diffbase.VPC]
}

func NewVPC(wholeCache *cache.Cache, cloudData []cloudmodel.VPC) *VPC {
	updater := &VPC{
		UpdaterBase[cloudmodel.VPC, mysql.VPC, *diffbase.VPC]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_VPC_EN,
			cache:        wholeCache,
			dbOperator:   db.NewVPC(),
			diffBaseData: wholeCache.DiffBaseDataSet.VPCs,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (v *VPC) getDiffBaseByCloudItem(cloudItem *cloudmodel.VPC) (diffBase *diffbase.VPC, exists bool) {
	diffBase, exists = v.diffBaseData[cloudItem.Lcuuid]
	return
}

func (v *VPC) generateDBItemToAdd(cloudItem *cloudmodel.VPC) (*mysql.VPC, bool) {
	dbItem := &mysql.VPC{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		UID:          cloudItem.Label,
		CreateMethod: ctrlrcommon.CREATE_METHOD_LEARN,
		Domain:       v.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		CIDR:         cloudItem.CIDR,
		TunnelID:     cloudItem.TunnelID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (v *VPC) generateUpdateInfo(diffBase *diffbase.VPC, cloudItem *cloudmodel.VPC) (map[string]interface{}, bool) {
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
	if diffBase.CIDR != cloudItem.CIDR {
		updateInfo["cidr"] = cloudItem.CIDR
	}
	if diffBase.TunnelID != cloudItem.TunnelID {
		updateInfo["tunnel_id"] = cloudItem.TunnelID
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
