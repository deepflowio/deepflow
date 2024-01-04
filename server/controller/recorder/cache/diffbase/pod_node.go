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

func (b *DataSet) AddPodNode(dbItem *mysql.PodNode, seq int) {
	b.PodNodes[dbItem.Lcuuid] = &PodNode{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Type:            dbItem.Type,
		State:           dbItem.State,
		VCPUNum:         dbItem.VCPUNum,
		MemTotal:        dbItem.MemTotal,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, b.PodNodes[dbItem.Lcuuid]))
}

func (b *DataSet) DeletePodNode(lcuuid string) {
	delete(b.PodNodes, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, lcuuid))
}

type PodNode struct {
	DiffBase
	Type            int    `json:"type"`
	State           int    `json:"state"`
	VCPUNum         int    `json:"vcpu_num"`
	MemTotal        int    `json:"mem_total"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodNode) Update(cloudItem *cloudmodel.PodNode) {
	p.Type = cloudItem.Type
	p.State = cloudItem.State
	p.VCPUNum = cloudItem.VCPUNum
	p.MemTotal = cloudItem.MemTotal
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, p))
}
