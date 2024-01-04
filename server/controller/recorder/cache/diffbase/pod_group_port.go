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

func (b *DataSet) AddPodGroupPort(dbItem *mysql.PodGroupPort, seq int) {
	b.PodGroupPorts[dbItem.Lcuuid] = &PodGroupPort{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, b.PodGroupPorts[dbItem.Lcuuid]))
}

func (b *DataSet) DeletePodGroupPort(lcuuid string) {
	delete(b.PodGroupPorts, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, lcuuid))
}

type PodGroupPort struct {
	DiffBase
	Name            string `json:"name"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodGroupPort) Update(cloudItem *cloudmodel.PodGroupPort) {
	p.Name = cloudItem.Name
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, p))
}
