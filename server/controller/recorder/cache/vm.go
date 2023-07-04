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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func (b *DiffBaseDataSet) addVM(dbItem *mysql.VM, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	newItem := &VM{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		VPCLcuuid:    vpcLcuuid,
		State:        dbItem.State,
		HType:        dbItem.HType,
		LaunchServer: dbItem.LaunchServer,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		CloudTags:    dbItem.CloudTags,
	}
	b.VMs[dbItem.Lcuuid] = newItem
	b.GetLogFunc()(addDiffBase(RESOURCE_TYPE_VM_EN, b.VMs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVM(lcuuid string) {
	delete(b.VMs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VM_EN, lcuuid))
}

type VM struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	State        int    `json:"state"`
	HType        int    `json:"htype"`
	LaunchServer string `json:"launch_server"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
	CloudTags    string `json:"cloud_tags"`
}

func (v *VM) Update(cloudItem *cloudmodel.VM) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.State = cloudItem.State
	v.HType = cloudItem.HType
	v.LaunchServer = cloudItem.LaunchServer
	v.VPCLcuuid = cloudItem.VPCLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	v.AZLcuuid = cloudItem.AZLcuuid
	v.CloudTags = cloudItem.CloudTags
	log.Info(updateDiffBase(RESOURCE_TYPE_VM_EN, v))
}
