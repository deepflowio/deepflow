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

func (b *DataSet) AddDHCPPort(dbItem *mysql.DHCPPort, seq int, toolDataSet *tool.DataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.DHCPPorts[dbItem.Lcuuid] = &DHCPPort{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		VPCLcuuid:    vpcLcuuid,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, b.DHCPPorts[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteDHCPPort(lcuuid string) {
	delete(b.DHCPPorts, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, lcuuid))
}

type DHCPPort struct {
	DiffBase
	Name         string `json:"name"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
}

func (d *DHCPPort) Update(cloudItem *cloudmodel.DHCPPort) {
	d.Name = cloudItem.Name
	d.RegionLcuuid = cloudItem.RegionLcuuid
	d.AZLcuuid = cloudItem.AZLcuuid
	d.VPCLcuuid = cloudItem.VPCLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, d))
}
