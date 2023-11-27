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

func (b *DataSet) AddRDSInstance(dbItem *mysql.RDSInstance, seq int) {
	b.RDSInstances[dbItem.Lcuuid] = &RDSInstance{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		State:        dbItem.State,
		Series:       dbItem.Series,
		Model:        dbItem.Model,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, b.RDSInstances[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteRDSInstance(lcuuid string) {
	delete(b.RDSInstances, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, lcuuid))
}

type RDSInstance struct {
	DiffBase
	Name         string `json:"name"`
	State        int    `json:"state"`
	Series       int    `json:"series"`
	Model        int    `json:"model"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (r *RDSInstance) Update(cloudItem *cloudmodel.RDSInstance) {
	r.Name = cloudItem.Name
	r.State = cloudItem.State
	r.Series = cloudItem.Series
	r.Model = cloudItem.Model
	r.VPCLcuuid = cloudItem.VPCLcuuid
	r.RegionLcuuid = cloudItem.RegionLcuuid
	r.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, r))
}
