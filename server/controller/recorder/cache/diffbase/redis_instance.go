/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddRedisInstance(dbItem *mysql.RedisInstance, seq int) {
	b.RedisInstances[dbItem.Lcuuid] = &RedisInstance{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		State:        dbItem.State,
		PublicHost:   dbItem.PublicHost,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, b.RedisInstances[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteRedisInstance(lcuuid string) {
	delete(b.RedisInstances, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, lcuuid))
}

type RedisInstance struct {
	DiffBase
	Name         string `json:"name"`
	State        int    `json:"state"`
	PublicHost   string `json:"public_host"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (r *RedisInstance) Update(cloudItem *cloudmodel.RedisInstance) {
	r.Name = cloudItem.Name
	r.State = cloudItem.State
	r.PublicHost = cloudItem.PublicHost
	r.RegionLcuuid = cloudItem.RegionLcuuid
	r.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, r))
}
