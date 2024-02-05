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

type VPC struct {
	UpdaterBase[
		cloudmodel.VPC,
		mysql.VPC,
		*diffbase.VPC,
		*message.VPCAdd,
		message.VPCAdd,
		*message.VPCUpdate,
		message.VPCUpdate,
		*message.VPCFieldsUpdate,
		message.VPCFieldsUpdate,
		*message.VPCDelete,
		message.VPCDelete]
}

func NewVPC(wholeCache *cache.Cache, cloudData []cloudmodel.VPC) *VPC {
	updater := &VPC{
		newUpdaterBase[
			cloudmodel.VPC,
			mysql.VPC,
			*diffbase.VPC,
			*message.VPCAdd,
			message.VPCAdd,
			*message.VPCUpdate,
			message.VPCUpdate,
			*message.VPCFieldsUpdate,
			message.VPCFieldsUpdate,
			*message.VPCDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VPC_EN,
			wholeCache,
			db.NewVPC(),
			wholeCache.DiffBaseDataSet.VPCs,
			cloudData,
		),
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

func (v *VPC) generateUpdateInfo(diffBase *diffbase.VPC, cloudItem *cloudmodel.VPC) (*message.VPCFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VPCFieldsUpdate)
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
	if diffBase.CIDR != cloudItem.CIDR {
		mapInfo["cidr"] = cloudItem.CIDR
		structInfo.CIDR.Set(diffBase.CIDR, cloudItem.CIDR)
	}
	if diffBase.TunnelID != cloudItem.TunnelID {
		mapInfo["tunnel_id"] = cloudItem.TunnelID
		structInfo.TunnelID.Set(diffBase.TunnelID, cloudItem.TunnelID)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
