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

type SubDomain struct {
	ResourceBase
	Name string
}

func (a *SubDomain) reset(dbItem *metadbmodel.SubDomain, tool *tool.Tool) {
	a.Name = dbItem.Name
}

func NewSubDomainCollection(t *tool.Tool) *SubDomainCollection {
	c := new(SubDomainCollection)
	c.collection = newCollectionBuilder[*SubDomain]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.SubDomain { return new(metadbmodel.SubDomain) }).
		withCacheItemFactory(func() *SubDomain { return new(SubDomain) }).
		build()
	return c
}

type SubDomainCollection struct {
	collection[*SubDomain, *metadbmodel.SubDomain]
}
