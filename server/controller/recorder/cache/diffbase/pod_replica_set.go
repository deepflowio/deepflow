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

type PodReplicaSet struct {
	ResourceBase
	Name            string
	Label           string
	PodNum          int
	RegionLcuuid    string
	AZLcuuid        string
	SubDomainLcuuid string
}

func (a *PodReplicaSet) reset(dbItem *metadbmodel.PodReplicaSet, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.PodNum = dbItem.PodNum
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodReplicaSetCollection(t *tool.Tool) *PodReplicaSetCollection {
	c := new(PodReplicaSetCollection)
	c.collection = newCollectionBuilder[*PodReplicaSet]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodReplicaSet { return new(metadbmodel.PodReplicaSet) }).
		withCacheItemFactory(func() *PodReplicaSet { return new(PodReplicaSet) }).
		build()
	return c
}

type PodReplicaSetCollection struct {
	collection[*PodReplicaSet, *metadbmodel.PodReplicaSet]
}
