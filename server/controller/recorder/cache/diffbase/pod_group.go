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

type PodGroup struct {
	ResourceBase
	Name            string
	Label           string
	PodNum          int
	Type            int
	Metadata        string
	MetadataHash    string
	Spec            string
	SpecHash        string
	RegionLcuuid    string
	AZLcuuid        string
	SubDomainLcuuid string
	NetworkMode     int
}

func (a *PodGroup) reset(dbItem *metadbmodel.PodGroup, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.PodNum = dbItem.PodNum
	a.Type = dbItem.Type
	a.Metadata = string(dbItem.Metadata)
	a.MetadataHash = dbItem.MetadataHash
	a.Spec = string(dbItem.Spec)
	a.SpecHash = dbItem.SpecHash
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
	a.NetworkMode = dbItem.NetworkMode
}

// ToLoggable converts PodGroup to a loggable format, excluding sensitive fields
func (a PodGroup) ToLoggable() interface{} {
	copied := a
	copied.Metadata = "**HIDDEN**"
	copied.Spec = "**HIDDEN**"
	return copied
}

func NewPodGroupCollection(t *tool.Tool) *PodGroupCollection {
	c := new(PodGroupCollection)
	c.collection = newCollectionBuilder[*PodGroup]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodGroup { return new(metadbmodel.PodGroup) }).
		withCacheItemFactory(func() *PodGroup { return new(PodGroup) }).
		build()
	return c
}

type PodGroupCollection struct {
	collection[*PodGroup, *metadbmodel.PodGroup]
}
