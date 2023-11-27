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

func (b *DataSet) AddPodNamespace(dbItem *mysql.PodNamespace, seq int) {
	b.PodNamespaces[dbItem.Lcuuid] = &PodNamespace{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
		CloudTags:       dbItem.CloudTags,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, b.PodNamespaces[dbItem.Lcuuid]))
}

func (b *DataSet) DeletePodNamespace(lcuuid string) {
	delete(b.PodNamespaces, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, lcuuid))
}

type PodNamespace struct {
	DiffBase
	RegionLcuuid    string            `json:"region_lcuuid"`
	AZLcuuid        string            `json:"az_lcuuid"`
	SubDomainLcuuid string            `json:"sub_domain_lcuuid"`
	CloudTags       map[string]string `json:"cloud_tags"`
}

func (p *PodNamespace) Update(cloudItem *cloudmodel.PodNamespace) {
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.CloudTags = cloudItem.CloudTags
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, p))
}
