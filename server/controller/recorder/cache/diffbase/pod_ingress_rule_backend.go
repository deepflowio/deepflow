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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type PodIngressRuleBackend struct {
	ResourceBase
	SubDomainLcuuid string
}

func (a *PodIngressRuleBackend) reset(dbItem *metadbmodel.PodIngressRuleBackend, tool *tool.Tool) {
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodIngressRuleBackendCollection(t *tool.Tool) *PodIngressRuleBackendCollection {
	c := new(PodIngressRuleBackendCollection)
	c.collection = newCollectionBuilder[*PodIngressRuleBackend]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodIngressRuleBackend { return new(metadbmodel.PodIngressRuleBackend) }).
		withCacheItemFactory(func() *PodIngressRuleBackend { return new(PodIngressRuleBackend) }).
		build()
	return c
}

type PodIngressRuleBackendCollection struct {
	collection[*PodIngressRuleBackend, *metadbmodel.PodIngressRuleBackend]
}
