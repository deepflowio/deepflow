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

func (b *DataSet) AddSubnet(dbItem *mysql.Subnet, seq int) {
	b.Subnets[dbItem.Lcuuid] = &Subnet{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, b.Subnets[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteSubnet(lcuuid string) {
	delete(b.Subnets, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, lcuuid))
}

type Subnet struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (s *Subnet) Update(cloudItem *cloudmodel.Subnet) {
	s.Name = cloudItem.Name
	s.Label = cloudItem.Label
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, s))
}
