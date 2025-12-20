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

type RDSInstance struct {
	ResourceBase
	Name         string
	State        int
	Series       int
	Model        int
	VPCLcuuid    string
	RegionLcuuid string
	AZLcuuid     string
}

func (a *RDSInstance) reset(dbItem *metadbmodel.RDSInstance, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.State = dbItem.State
	a.Series = dbItem.Series
	a.Model = dbItem.Model
	a.VPCLcuuid = tool.VPC().GetByID(dbItem.VPCID).Lcuuid()
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
}

func NewRDSInstanceCollection(t *tool.Tool) *RDSInstanceCollection {
	c := new(RDSInstanceCollection)
	c.collection = newCollectionBuilder[*RDSInstance]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.RDSInstance { return new(metadbmodel.RDSInstance) }).
		withCacheItemFactory(func() *RDSInstance { return new(RDSInstance) }).
		build()
	return c
}

type RDSInstanceCollection struct {
	collection[*RDSInstance, *metadbmodel.RDSInstance]
}
