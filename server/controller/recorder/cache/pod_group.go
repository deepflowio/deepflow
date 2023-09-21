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

func (b *DiffBaseDataSet) addPodGroup(dbItem *mysql.PodGroup, seq int) {
	b.PodGroups[dbItem.Lcuuid] = &PodGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		PodNum:          dbItem.PodNum,
		Type:            dbItem.Type,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(RESOURCE_TYPE_POD_GROUP_EN, b.PodGroups[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodGroup(lcuuid string) {
	delete(b.PodGroups, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_GROUP_EN, lcuuid))
}

type PodGroup struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	PodNum          int    `json:"pod_num"`
	Type            int    `json:"type"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodGroup) Update(cloudItem *cloudmodel.PodGroup) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.PodNum = cloudItem.PodNum
	p.Type = cloudItem.Type
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_GROUP_EN, p))
}
