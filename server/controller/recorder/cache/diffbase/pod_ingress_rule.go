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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddPodIngressRule(dbItem *mysql.PodIngressRule, seq int) {
	b.PodIngressRules[dbItem.Lcuuid] = &PodIngressRule{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, b.PodIngressRules[dbItem.Lcuuid]))
}

func (b *DataSet) DeletePodIngressRule(lcuuid string) {
	delete(b.PodIngressRules, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, lcuuid))
}

type PodIngressRule struct {
	DiffBase
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}
