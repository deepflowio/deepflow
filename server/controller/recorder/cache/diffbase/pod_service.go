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

type PodService struct {
	ResourceBase
	Name             string
	Label            string
	Annotation       string
	Selector         string
	ExternalIP       string
	ServiceClusterIP string
	Metadata         string
	MetadataHash     string
	Spec             string
	SpecHash         string
	PodIngressLcuuid string
	RegionLcuuid     string
	AZLcuuid         string
	SubDomainLcuuid  string
}

func (a *PodService) reset(dbItem *metadbmodel.PodService, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.Annotation = dbItem.Annotation
	a.Selector = dbItem.Selector
	a.ExternalIP = dbItem.ExternalIP
	a.ServiceClusterIP = dbItem.ServiceClusterIP
	a.Metadata = string(dbItem.Metadata)
	a.MetadataHash = dbItem.MetadataHash
	a.Spec = string(dbItem.Spec)
	a.SpecHash = dbItem.SpecHash
	a.PodIngressLcuuid = tool.PodIngress().GetByID(dbItem.PodIngressID).Lcuuid()
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.SubDomainLcuuid = dbItem.SubDomain
}

// ToLoggable converts PodService to a loggable format, excluding sensitive fields
func (a PodService) ToLoggable() interface{} {
	copied := a
	copied.Metadata = "**HIDDEN**"
	copied.Spec = "**HIDDEN**"
	return copied
}

func NewPodServiceCollection(t *tool.Tool) *PodServiceCollection {
	c := new(PodServiceCollection)
	c.collection = newCollectionBuilder[*PodService]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodService { return new(metadbmodel.PodService) }).
		withCacheItemFactory(func() *PodService { return new(PodService) }).
		build()
	return c
}

type PodServiceCollection struct {
	collection[*PodService, *metadbmodel.PodService]
}
