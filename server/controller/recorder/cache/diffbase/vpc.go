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

func (b *DataSet) AddVPC(dbItem *mysql.VPC, seq int) {
	b.VPCs[dbItem.Lcuuid] = &VPC{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		TunnelID:     dbItem.TunnelID,
		CIDR:         dbItem.CIDR,
		RegionLcuuid: dbItem.Region,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VPC_EN, b.VPCs[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteVPC(lcuuid string) {
	delete(b.VPCs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VPC_EN, lcuuid))
}

type VPC struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	TunnelID     int    `json:"tunnel_id"`
	CIDR         string `json:"cidr"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (v *VPC) Update(cloudItem *cloudmodel.VPC) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.TunnelID = cloudItem.TunnelID
	v.CIDR = cloudItem.CIDR
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VPC_EN, v))
}
