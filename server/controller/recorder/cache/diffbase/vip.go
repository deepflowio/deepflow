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

func (b *DataSet) AddVIP(dbItem *mysql.VIP, seq int) {
	b.VIP[dbItem.Lcuuid] = &VIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		IP:     dbItem.IP,
		VTapID: dbItem.VTapID,
	}
	log.Info(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VIP_EN, b.VIP[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteVIP(lcuuid string) {
	delete(b.VIP, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VIP_EN, lcuuid))
}

type VIP struct {
	DiffBase
	IP     string `json:"ip" binding:"required"`
	VTapID uint32 `json:"vtap_id" binding:"required"`
}

func (p *VIP) Update(cloudItem *cloudmodel.VIP) {
	p.IP = cloudItem.IP
	p.VTapID = cloudItem.VTapID
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VIP_EN, p))
}
