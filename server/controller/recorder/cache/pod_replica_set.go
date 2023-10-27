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

func (b *DiffBaseDataSet) addPodReplicaSet(dbItem *mysql.PodReplicaSet, seq int) {
	b.PodReplicaSets[dbItem.Lcuuid] = &PodReplicaSet{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		PodNum:          dbItem.PodNum,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, b.PodReplicaSets[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodReplicaSet(lcuuid string) {
	delete(b.PodReplicaSets, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, lcuuid))
}

type PodReplicaSet struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	PodNum          int    `json:"pod_num"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodReplicaSet) Update(cloudItem *cloudmodel.PodReplicaSet) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.PodNum = cloudItem.PodNum
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, p))
}
