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

type PodGroupPort struct {
	ResourceBase
	Name            string
	SubDomainLcuuid string
}

func (a *PodGroupPort) reset(dbItem *metadbmodel.PodGroupPort, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodGroupPortCollection(t *tool.Tool) *PodGroupPortCollection {
	c := new(PodGroupPortCollection)
	c.collection = newCollectionBuilder[*PodGroupPort]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodGroupPort { return new(metadbmodel.PodGroupPort) }).
		withCacheItemFactory(func() *PodGroupPort { return new(PodGroupPort) }).
		build()
	return c
}

type PodGroupPortCollection struct {
	collection[*PodGroupPort, *metadbmodel.PodGroupPort]
}
