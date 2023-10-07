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
)

func (b *DiffBaseDataSet) addFloatingIP(dbItem *mysql.FloatingIP, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.FloatingIPs[dbItem.Lcuuid] = &FloatingIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid: dbItem.Region,
		VPCLcuuid:    vpcLcuuid,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, b.FloatingIPs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteFloatingIP(lcuuid string) {
	delete(b.FloatingIPs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, lcuuid))
}

type FloatingIP struct {
	DiffBase
	RegionLcuuid string `json:"region_lcuuid"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
}

func (f *FloatingIP) Update(cloudItem *cloudmodel.FloatingIP) {
	f.RegionLcuuid = cloudItem.RegionLcuuid
	f.VPCLcuuid = cloudItem.VPCLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, f))
}
