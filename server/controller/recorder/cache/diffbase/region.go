/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddRegion(dbItem *mysql.Region, seq int) {
	b.Regions[dbItem.Lcuuid] = &Region{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:  dbItem.Name,
		Label: dbItem.Label,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_REGION_EN, b.Regions[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteRegion(lcuuid string) {
	delete(b.Regions, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_REGION_EN, lcuuid))
}

type Region struct {
	DiffBase
	Name  string `json:"name"`
	Label string `json:"label"`
}

func (r *Region) Update(cloudItem *cloudmodel.Region) {
	r.Name = cloudItem.Name
	r.Label = cloudItem.Label
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_REGION_EN, r))
}
