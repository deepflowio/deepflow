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

type RDSInstance struct {
	UpdaterBase[
		cloudmodel.RDSInstance,
		mysql.RDSInstance,
		*diffbase.RDSInstance,
		*message.RDSInstanceAdd,
		message.RDSInstanceAdd,
		*message.RDSInstanceUpdate,
		message.RDSInstanceUpdate,
		*message.RDSInstanceFieldsUpdate,
		message.RDSInstanceFieldsUpdate,
		*message.RDSInstanceDelete,
		message.RDSInstanceDelete]
}

func NewRDSInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RDSInstance) *RDSInstance {
	updater := &RDSInstance{
		newUpdaterBase[
			cloudmodel.RDSInstance,
			mysql.RDSInstance,
			*diffbase.RDSInstance,
			*message.RDSInstanceAdd,
			message.RDSInstanceAdd,
			*message.RDSInstanceUpdate,
			message.RDSInstanceUpdate,
			*message.RDSInstanceFieldsUpdate,
			message.RDSInstanceFieldsUpdate,
			*message.RDSInstanceDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN,
			wholeCache,
			db.NewRDSInstance().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.RDSInstances,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *RDSInstance) getDiffBaseByCloudItem(cloudItem *cloudmodel.RDSInstance) (diffBase *diffbase.RDSInstance, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *RDSInstance) generateDBItemToAdd(cloudItem *cloudmodel.RDSInstance) (*mysql.RDSInstance, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(r.metadata.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}
	dbItem := &mysql.RDSInstance{
		Name:    cloudItem.Name,
		Label:   cloudItem.Label,
		UID:     cloudItem.Label,
		State:   cloudItem.State,
		Type:    cloudItem.Type,
		Version: cloudItem.Version,
		Series:  cloudItem.Series,
		Model:   cloudItem.Model,
		Domain:  r.metadata.Domain.Lcuuid,
		Region:  cloudItem.RegionLcuuid,
		AZ:      cloudItem.AZLcuuid,
		VPCID:   vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RDSInstance) generateUpdateInfo(diffBase *diffbase.RDSInstance, cloudItem *cloudmodel.RDSInstance) (*message.RDSInstanceFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.RDSInstanceFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.State != cloudItem.State {
		mapInfo["state"] = cloudItem.State
		structInfo.State.Set(diffBase.State, cloudItem.State)
	}
	if diffBase.Series != cloudItem.Series {
		mapInfo["series"] = cloudItem.Series
		structInfo.Series.Set(diffBase.Series, cloudItem.Series)
	}
	if diffBase.Model != cloudItem.Model {
		mapInfo["model"] = cloudItem.Model
		structInfo.Model.Set(diffBase.Model, cloudItem.Model)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
