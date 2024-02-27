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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type VRouter struct {
	UpdaterBase[
		cloudmodel.VRouter,
		mysql.VRouter,
		*diffbase.VRouter,
		*message.VRouterAdd,
		message.VRouterAdd,
		*message.VRouterUpdate,
		message.VRouterUpdate,
		*message.VRouterFieldsUpdate,
		message.VRouterFieldsUpdate,
		*message.VRouterDelete,
		message.VRouterDelete]
}

func NewVRouter(wholeCache *cache.Cache, cloudData []cloudmodel.VRouter) *VRouter {
	updater := &VRouter{
		newUpdaterBase[
			cloudmodel.VRouter,
			mysql.VRouter,
			*diffbase.VRouter,
			*message.VRouterAdd,
			message.VRouterAdd,
			*message.VRouterUpdate,
			message.VRouterUpdate,
			*message.VRouterFieldsUpdate,
			message.VRouterFieldsUpdate,
			*message.VRouterDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN,
			wholeCache,
			db.NewVRouter(),
			wholeCache.DiffBaseDataSet.VRouters,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *VRouter) getDiffBaseByCloudItem(cloudItem *cloudmodel.VRouter) (diffBase *diffbase.VRouter, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *VRouter) generateDBItemToAdd(cloudItem *cloudmodel.VRouter) (*mysql.VRouter, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.VRouter{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		State:          rcommon.VROUTER_STATE_RUNNING,
		GWLaunchServer: cloudItem.GWLaunchServer,
		Domain:         r.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		VPCID:          vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *VRouter) generateUpdateInfo(diffBase *diffbase.VRouter, cloudItem *cloudmodel.VRouter) (*message.VRouterFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VRouterFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cloudItem.Lcuuid,
			))
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID)
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
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
