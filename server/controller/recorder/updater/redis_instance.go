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

type RedisInstance struct {
	UpdaterBase[
		cloudmodel.RedisInstance,
		mysql.RedisInstance,
		*diffbase.RedisInstance,
		*message.RedisInstanceAdd,
		message.RedisInstanceAdd,
		*message.RedisInstanceUpdate,
		message.RedisInstanceUpdate,
		*message.RedisInstanceFieldsUpdate,
		message.RedisInstanceFieldsUpdate,
		*message.RedisInstanceDelete,
		message.RedisInstanceDelete]
}

func NewRedisInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RedisInstance) *RedisInstance {
	updater := &RedisInstance{
		newUpdaterBase[
			cloudmodel.RedisInstance,
			mysql.RedisInstance,
			*diffbase.RedisInstance,
			*message.RedisInstanceAdd,
			message.RedisInstanceAdd,
			*message.RedisInstanceUpdate,
			message.RedisInstanceUpdate,
			*message.RedisInstanceFieldsUpdate,
			message.RedisInstanceFieldsUpdate,
			*message.RedisInstanceDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN,
			wholeCache,
			db.NewRedisInstance().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.RedisInstances,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *RedisInstance) getDiffBaseByCloudItem(cloudItem *cloudmodel.RedisInstance) (diffBase *diffbase.RedisInstance, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *RedisInstance) generateDBItemToAdd(cloudItem *cloudmodel.RedisInstance) (*mysql.RedisInstance, bool) {
	vpcID, exists := r.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, cloudItem.Lcuuid,
		)
		return nil, false
	}
	dbItem := &mysql.RedisInstance{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		UID:          cloudItem.Label,
		State:        cloudItem.State,
		Version:      cloudItem.Version,
		InternalHost: cloudItem.InternalHost,
		PublicHost:   cloudItem.PublicHost,
		Domain:       r.metadata.Domain.Lcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RedisInstance) generateUpdateInfo(diffBase *diffbase.RedisInstance, cloudItem *cloudmodel.RedisInstance) (*message.RedisInstanceFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.RedisInstanceFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.State != cloudItem.State {
		mapInfo["state"] = cloudItem.State
		structInfo.State.Set(diffBase.State, cloudItem.State)
	}
	if diffBase.PublicHost != cloudItem.PublicHost {
		mapInfo["public_host"] = cloudItem.PublicHost
		structInfo.PublicHost.Set(diffBase.PublicHost, cloudItem.PublicHost)
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
