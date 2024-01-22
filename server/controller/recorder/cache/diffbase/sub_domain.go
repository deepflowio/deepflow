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
)

func (b *DataSet) AddSubDomain(dbItem *mysql.SubDomain, seq int) {
	b.SubDomains[dbItem.Lcuuid] = &SubDomain{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name: dbItem.Name,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, b.SubDomains[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteSubDomain(lcuuid string) {
	delete(b.SubDomains, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, lcuuid))
}

type SubDomain struct {
	DiffBase
	Name string `json:"name"`
}

func (s *SubDomain) Update(cloudItem *cloudmodel.SubDomain) {
	s.Name = cloudItem.Name
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, s))
}
