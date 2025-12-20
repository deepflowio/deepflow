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

type PodCluster struct {
	ResourceBase
	Name            string
	ClusterName     string
	RegionLcuuid    string
	AZLcuuid        string
	SubDomainLcuuid string
}

func (a *PodCluster) reset(dbItem *metadbmodel.PodCluster, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.ClusterName = dbItem.ClusterName
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodClusterCollection(t *tool.Tool) *PodClusterCollection {
	c := new(PodClusterCollection)
	c.collection = newCollectionBuilder[*PodCluster]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodCluster { return new(metadbmodel.PodCluster) }).
		withCacheItemFactory(func() *PodCluster { return new(PodCluster) }).
		build()
	return c
}

type PodClusterCollection struct {
	collection[*PodCluster, *metadbmodel.PodCluster]
}
