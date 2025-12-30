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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type RDSInstance struct {
	UpdaterBase[
		cloudmodel.RDSInstance,
		*diffbase.RDSInstance,
		*metadbmodel.RDSInstance,
		metadbmodel.RDSInstance,
		*message.AddedRDSInstances,
		message.AddedRDSInstances,
		message.AddNoneAddition,
		*message.UpdatedRDSInstance,
		message.UpdatedRDSInstance,
		*message.UpdatedRDSInstanceFields,
		message.UpdatedRDSInstanceFields,
		*message.DeletedRDSInstances,
		message.DeletedRDSInstances,
		message.DeleteNoneAddition]
}

func NewRDSInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RDSInstance) *RDSInstance {
	updater := &RDSInstance{
		newUpdaterBase[
			cloudmodel.RDSInstance,
			*diffbase.RDSInstance,
			*metadbmodel.RDSInstance,
			metadbmodel.RDSInstance,
			*message.AddedRDSInstances,
			message.AddedRDSInstances,
			message.AddNoneAddition,
			*message.UpdatedRDSInstance,
			message.UpdatedRDSInstance,
			*message.UpdatedRDSInstanceFields,
			message.UpdatedRDSInstanceFields,
			*message.DeletedRDSInstances,
			message.DeletedRDSInstances,
			message.DeleteNoneAddition,
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

func (r *RDSInstance) generateDBItemToAdd(cloudItem *cloudmodel.RDSInstance) (*metadbmodel.RDSInstance, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, cloudItem.Lcuuid,
		), r.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.RDSInstance{
		Name:    cloudItem.Name,
		Label:   cloudItem.Label,
		UID:     cloudItem.Label,
		State:   cloudItem.State,
		Type:    cloudItem.Type,
		Version: cloudItem.Version,
		Series:  cloudItem.Series,
		Model:   cloudItem.Model,
		Domain:  r.metadata.GetDomainLcuuid(),
		Region:  cloudItem.RegionLcuuid,
		AZ:      cloudItem.AZLcuuid,
		VPCID:   vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RDSInstance) generateUpdateInfo(diffBase *diffbase.RDSInstance, cloudItem *cloudmodel.RDSInstance) (*message.UpdatedRDSInstanceFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedRDSInstanceFields)
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
