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

type PodServicePort struct {
	ResourceBase
	Name            string
	SubDomainLcuuid string
}

func (a *PodServicePort) reset(dbItem *metadbmodel.PodServicePort, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodServicePortCollection(t *tool.Tool) *PodServicePortCollection {
	c := new(PodServicePortCollection)
	c.collection = newCollectionBuilder[*PodServicePort]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodServicePort { return new(metadbmodel.PodServicePort) }).
		withCacheItemFactory(func() *PodServicePort { return new(PodServicePort) }).
		build()
	return c
}

type PodServicePortCollection struct {
	collection[*PodServicePort, *metadbmodel.PodServicePort]
}
