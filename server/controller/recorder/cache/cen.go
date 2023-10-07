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

package cache

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func (b *DiffBaseDataSet) addCEN(dbItem *mysql.CEN, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuids := []string{}
	for _, vpcID := range rcommon.StringToIntSlice(dbItem.VPCIDs) {
		vpcLcuuid, exists := toolDataSet.GetVPCLcuuidByID(vpcID)
		if exists {
			vpcLcuuids = append(vpcLcuuids, vpcLcuuid)
		}
	}
	b.CENs[dbItem.Lcuuid] = &CEN{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:       dbItem.Name,
		VPCLcuuids: vpcLcuuids,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, b.CENs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteCEN(lcuuid string) {
	delete(b.CENs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, lcuuid))
}

type CEN struct {
	DiffBase
	Name       string   `json:"name"`
	VPCLcuuids []string `json:"vpc_lcuuids"`
}

func (c *CEN) Update(cloudItem *cloudmodel.CEN) {
	c.Name = cloudItem.Name
	c.VPCLcuuids = cloudItem.VPCLcuuids
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, c))
}
