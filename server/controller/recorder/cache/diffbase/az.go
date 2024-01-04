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

func (b *DataSet) AddAZ(dbItem *mysql.AZ, seq int) {
	b.AZs[dbItem.Lcuuid] = &AZ{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		RegionLcuuid: dbItem.Region,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_AZ_EN, b.AZs[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteAZ(lcuuid string) {
	delete(b.AZs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_AZ_EN, lcuuid))
}

type AZ struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (a *AZ) Update(cloudItem *cloudmodel.AZ) {
	a.Name = cloudItem.Name
	a.Label = cloudItem.Label
	a.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_AZ_EN, a))
}
