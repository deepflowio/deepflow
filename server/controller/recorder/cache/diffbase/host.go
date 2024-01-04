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

func (b *DataSet) AddHost(dbItem *mysql.Host, seq int) {
	b.Hosts[dbItem.Lcuuid] = &Host{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		IP:           dbItem.IP,
		HType:        dbItem.HType,
		VCPUNum:      dbItem.VCPUNum,
		MemTotal:     dbItem.MemTotal,
		ExtraInfo:    dbItem.ExtraInfo,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_HOST_EN, b.Hosts[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteHost(lcuuid string) {
	delete(b.Hosts, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_HOST_EN, lcuuid))
}

type Host struct {
	DiffBase
	Name         string `json:"name"`
	IP           string `json:"ip"`
	HType        int    `json:"htype"`
	VCPUNum      int    `json:"vcpu_num"`
	MemTotal     int    `json:"mem_total"`
	ExtraInfo    string `json:"extra_info"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (h *Host) Update(cloudItem *cloudmodel.Host) {
	h.Name = cloudItem.Name
	h.IP = cloudItem.IP
	h.HType = cloudItem.HType
	h.VCPUNum = cloudItem.VCPUNum
	h.MemTotal = cloudItem.MemTotal
	h.ExtraInfo = cloudItem.ExtraInfo
	h.RegionLcuuid = cloudItem.RegionLcuuid
	h.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_HOST_EN, h))
}
