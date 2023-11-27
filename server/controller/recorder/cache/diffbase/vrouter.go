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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddVRouter(dbItem *mysql.VRouter, seq int, toolDataSet *tool.DataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.VRouters[dbItem.Lcuuid] = &VRouter{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		VPCLcuuid:    vpcLcuuid,
		RegionLcuuid: dbItem.Region,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, b.VRouters[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteVRouter(lcuuid string) {
	delete(b.VRouters, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, lcuuid))
}

type VRouter struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (v *VRouter) Update(cloudItem *cloudmodel.VRouter) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.VPCLcuuid = cloudItem.VPCLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, v))
}
