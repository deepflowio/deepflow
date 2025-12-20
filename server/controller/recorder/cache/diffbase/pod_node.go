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

type PodNode struct {
	ResourceBase
	Type            int
	State           int
	Hostname        string
	IP              string
	VCPUNum         int
	MemTotal        int
	RegionLcuuid    string
	AZLcuuid        string
	SubDomainLcuuid string
}

func (a *PodNode) reset(dbItem *metadbmodel.PodNode, tool *tool.Tool) {
	a.Type = dbItem.Type
	a.State = dbItem.State
	a.Hostname = dbItem.Hostname
	a.IP = dbItem.IP
	a.VCPUNum = dbItem.VCPUNum
	a.MemTotal = dbItem.MemTotal
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodNodeCollection(t *tool.Tool) *PodNodeCollection {
	c := new(PodNodeCollection)
	c.collection = newCollectionBuilder[*PodNode]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodNode { return new(metadbmodel.PodNode) }).
		withCacheItemFactory(func() *PodNode { return new(PodNode) }).
		build()
	return c
}

type PodNodeCollection struct {
	collection[*PodNode, *metadbmodel.PodNode]
}
