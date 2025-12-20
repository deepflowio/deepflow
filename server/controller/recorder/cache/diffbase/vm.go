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

type VM struct {
	ResourceBase
	Name             string
	Label            string
	IP               string
	Hostname         string
	State            int
	HType            int
	LaunchServer     string
	VPCLcuuid        string
	RegionLcuuid     string
	AZLcuuid         string
	LearnedCloudTags map[string]string
	NetworkLcuuid    string
	HostID           int
}

func (a *VM) reset(dbItem *metadbmodel.VM, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.IP = dbItem.IP
	a.Hostname = dbItem.Hostname
	a.State = dbItem.State
	a.HType = dbItem.HType
	a.LaunchServer = dbItem.LaunchServer
	a.VPCLcuuid = tool.VPC().GetByID(dbItem.VPCID).Lcuuid()
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
	a.LearnedCloudTags = dbItem.LearnedCloudTags
	a.NetworkLcuuid = tool.Network().GetByID(dbItem.NetworkID).Lcuuid()
	a.HostID = tool.Host().GetByIP(dbItem.LaunchServer).ID()
}

func NewVMCollection(t *tool.Tool) *VMCollection {
	c := new(VMCollection)
	c.collection = newCollectionBuilder[*VM]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VM_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VM { return new(metadbmodel.VM) }).
		withCacheItemFactory(func() *VM { return new(VM) }).
		build()
	return c
}

type VMCollection struct {
	collection[*VM, *metadbmodel.VM]
}
