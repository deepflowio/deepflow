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

func (b *DataSet) AddWANIP(dbItem *mysql.WANIP, seq int, toolDataSet *tool.DataSet) {
	var subnetLcuuid string
	if dbItem.SubnetID != 0 {
		subnetLcuuid, _ = toolDataSet.GetSubnetLcuuidByID(dbItem.SubnetID)
	}
	b.WANIPs[dbItem.Lcuuid] = &WANIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid:    dbItem.Region,
		SubDomainLcuuid: dbItem.SubDomain,
		SubnetLcuuid:    subnetLcuuid,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, b.WANIPs[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteWANIP(lcuuid string) {
	delete(b.WANIPs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, lcuuid))
}

type WANIP struct {
	DiffBase
	RegionLcuuid    string `json:"region_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
	SubnetLcuuid    string `json:"subnet_lcuuid"`
}

func (w *WANIP) Update(cloudItem *cloudmodel.IP) {
	w.RegionLcuuid = cloudItem.RegionLcuuid
	w.SubnetLcuuid = cloudItem.SubnetLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, w))
}
