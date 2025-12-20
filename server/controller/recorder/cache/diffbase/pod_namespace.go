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

type PodNamespace struct {
	ResourceBase
	RegionLcuuid     string
	AZLcuuid         string
	SubDomainLcuuid  string
	LearnedCloudTags map[string]string
}

func (a *PodNamespace) reset(dbItem *metadbmodel.PodNamespace, tool *tool.Tool) {
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
	a.LearnedCloudTags = dbItem.LearnedCloudTags
}

func NewPodNamespaceCollection(t *tool.Tool) *PodNamespaceCollection {
	c := new(PodNamespaceCollection)
	c.collection = newCollectionBuilder[*PodNamespace]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodNamespace { return new(metadbmodel.PodNamespace) }).
		withCacheItemFactory(func() *PodNamespace { return new(PodNamespace) }).
		build()
	return c
}

type PodNamespaceCollection struct {
	collection[*PodNamespace, *metadbmodel.PodNamespace]
}
