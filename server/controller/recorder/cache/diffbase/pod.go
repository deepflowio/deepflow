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

type Pod struct {
	ResourceBase
	Name                string
	Label               string
	Annotation          string
	ENV                 string
	ContainerIDs        string
	State               int
	CreatedAt           time.Time
	PodNodeLcuuid       string
	PodReplicaSetLcuuid string
	PodGroupLcuuid      string
	PodServiceLcuuid    string
	VPCLcuuid           string
	RegionLcuuid        string
	AZLcuuid            string
	SubDomainLcuuid     string
}

func (a *Pod) reset(dbItem *metadbmodel.Pod, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.Annotation = dbItem.Annotation
	a.ENV = dbItem.ENV
	a.ContainerIDs = dbItem.ContainerIDs
	a.State = dbItem.State
	a.CreatedAt = dbItem.CreatedAt
	a.PodNodeLcuuid = tool.PodNode().GetByID(dbItem.PodNodeID).Lcuuid()
	a.PodReplicaSetLcuuid = tool.PodReplicaSet().GetByID(dbItem.PodReplicaSetID).Lcuuid()
	a.PodGroupLcuuid = tool.PodGroup().GetByID(dbItem.PodGroupID).Lcuuid()
	a.PodServiceLcuuid = tool.PodService().GetByID(dbItem.PodServiceID).Lcuuid()
	a.VPCLcuuid = tool.VPC().GetByID(dbItem.VPCID).Lcuuid()
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewPodCollection(t *tool.Tool) *PodCollection {
	c := new(PodCollection)
	c.collection = newCollectionBuilder[*Pod]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Pod { return new(metadbmodel.Pod) }).
		withCacheItemFactory(func() *Pod { return new(Pod) }).
		build()
	return c
}

type PodCollection struct {
	collection[*Pod, *metadbmodel.Pod]
}
