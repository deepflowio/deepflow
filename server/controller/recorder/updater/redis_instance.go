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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type RedisInstance struct {
	UpdaterBase[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]
}

func NewRedisInstance(wholeCache *cache.Cache, cloudData []cloudmodel.RedisInstance) *RedisInstance {
	updater := &RedisInstance{
		UpdaterBase[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN,
			cache:        wholeCache,
			dbOperator:   db.NewRedisInstance(),
			diffBaseData: wholeCache.RedisInstances,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (r *RedisInstance) getDiffBaseByCloudItem(cloudItem *cloudmodel.RedisInstance) (diffBase *cache.RedisInstance, exists bool) {
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
		Domain:       r.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *RedisInstance) generateUpdateInfo(diffBase *cache.RedisInstance, cloudItem *cloudmodel.RedisInstance) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.PublicHost != cloudItem.PublicHost {
		updateInfo["public_host"] = cloudItem.PublicHost
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
