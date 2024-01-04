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

func (b *DataSet) AddLB(dbItem *mysql.LB, seq int) {
	b.LBs[dbItem.Lcuuid] = &LB{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Model:        dbItem.Model,
		VIP:          dbItem.VIP,
		RegionLcuuid: dbItem.Region,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_EN, b.LBs[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteLB(lcuuid string) {
	delete(b.LBs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_EN, lcuuid))
}

type LB struct {
	DiffBase
	Name         string `json:"name"`
	Model        int    `json:"model"`
	VIP          string `json:"vip"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (l *LB) Update(cloudItem *cloudmodel.LB) {
	l.Name = cloudItem.Name
	l.Model = cloudItem.Model
	l.VIP = cloudItem.VIP
	l.VPCLcuuid = cloudItem.VPCLcuuid
	l.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_EN, l))
}
