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

func (b *DiffBaseDataSet) addPodNode(dbItem *mysql.PodNode, seq int) {
	b.PodNodes[dbItem.Lcuuid] = &PodNode{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		State:           dbItem.State,
		VCPUNum:         dbItem.VCPUNum,
		MemTotal:        dbItem.MemTotal,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(RESOURCE_TYPE_POD_NODE_EN, b.PodNodes[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodNode(lcuuid string) {
	delete(b.PodNodes, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_NODE_EN, lcuuid))
}

type PodNode struct {
	DiffBase
	State           int    `json:"state"`
	VCPUNum         int    `json:"vcpu_num"`
	MemTotal        int    `json:"mem_total"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodNode) Update(cloudItem *cloudmodel.PodNode) {
	p.State = cloudItem.State
	p.VCPUNum = cloudItem.VCPUNum
	p.MemTotal = cloudItem.MemTotal
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_NODE_EN, p))
}
