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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddVM(dbItem *mysql.VM, seq int, toolDataSet *tool.DataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	newItem := &VM{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		IP:           dbItem.IP,
		Hostname:     dbItem.Hostname,
		VPCLcuuid:    vpcLcuuid,
		State:        dbItem.State,
		HType:        dbItem.HType,
		LaunchServer: dbItem.LaunchServer,
		HostID:       dbItem.HostID,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		CloudTags:    dbItem.CloudTags,
	}
	b.VMs[dbItem.Lcuuid] = newItem
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_EN, b.VMs[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteVM(lcuuid string) {
	delete(b.VMs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_EN, lcuuid))
}

type VM struct {
	DiffBase
	Name         string            `json:"name"`
	Label        string            `json:"label"`
	IP           string            `json:"ip"`
	Hostname     string            `json:"hostname"`
	State        int               `json:"state"`
	HType        int               `json:"htype"`
	LaunchServer string            `json:"launch_server"`
	HostID       int               `json:"host_id"`
	VPCLcuuid    string            `json:"vpc_lcuuid"`
	RegionLcuuid string            `json:"region_lcuuid"`
	AZLcuuid     string            `json:"az_lcuuid"`
	CloudTags    map[string]string `json:"cloud_tags"`
}

func (v *VM) Update(cloudItem *cloudmodel.VM, toolDataSet *tool.DataSet) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.IP = cloudItem.IP
	v.Hostname = cloudItem.Hostname
	v.State = cloudItem.State
	v.HType = cloudItem.HType
	v.LaunchServer = cloudItem.LaunchServer
	v.VPCLcuuid = cloudItem.VPCLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	v.AZLcuuid = cloudItem.AZLcuuid
	v.CloudTags = cloudItem.CloudTags
	hostID, exists := toolDataSet.GetHostIDByIP(cloudItem.LaunchServer)
	if exists {
		v.HostID = hostID
	}
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_EN, v))
}
