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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func (b *DataSet) AddCEN(dbItem *metadbmodel.CEN, seq int, tool *tool.Tool) {
	vpcLcuuids := []string{}
	for _, vpcID := range rcommon.StringToIntSlice(dbItem.VPCIDs) {
		vpcLcuuid := tool.VPC().GetByID(vpcID).Lcuuid()
		if vpcLcuuid != "" {
			vpcLcuuids = append(vpcLcuuids, vpcLcuuid)
		}
	}
	b.CENs[dbItem.Lcuuid] = &CEN{
		ResourceBase: ResourceBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:       dbItem.Name,
		VPCLcuuids: vpcLcuuids,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, b.CENs[dbItem.Lcuuid]), b.metadata.LogPrefixes)
}

func (b *DataSet) DeleteCEN(lcuuid string) {
	delete(b.CENs, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, lcuuid), b.metadata.LogPrefixes)
}

func (c *CEN) Update(cloudItem *cloudmodel.CEN) {
	c.Name = cloudItem.Name
	c.VPCLcuuids = cloudItem.VPCLcuuids
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_CEN_EN, c))
}

type CEN struct {
	ResourceBase
	Name       string   `json:"name"`
	VPCLcuuids []string `json:"vpc_lcuuids"`
}

func (c *CEN) reset(dbItem *metadbmodel.CEN, tool *tool.Tool) {
	vpcLcuuids := []string{}
	for _, vpcID := range rcommon.StringToIntSlice(dbItem.VPCIDs) {
		vpcLcuuid := tool.VPC().GetByID(vpcID).Lcuuid()
		if vpcLcuuid != "" {
			vpcLcuuids = append(vpcLcuuids, vpcLcuuid)
		}
	}
	c.Name = dbItem.Name
	c.VPCLcuuids = vpcLcuuids
}

type CENCollection struct {
	collectionComponent[*CEN, CEN, *metadbmodel.CEN, metadbmodel.CEN]
}

func NewCENCollection(t *tool.Tool) *CENCollection {
	c := new(CENCollection)
	c.withResourceType(ctrlrcommon.RESOURCE_TYPE_CEN_EN).
		withTool(t).
		init()
	return c
}
