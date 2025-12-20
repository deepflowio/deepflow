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

type Host struct {
	ResourceBase
	Name         string
	IP           string
	Hostname     string
	HType        int
	VCPUNum      int
	MemTotal     int
	ExtraInfo    string
	RegionLcuuid string
	AZLcuuid     string
}

func (a *Host) reset(dbItem *metadbmodel.Host, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.IP = dbItem.IP
	a.Hostname = dbItem.Hostname
	a.HType = dbItem.HType
	a.VCPUNum = dbItem.VCPUNum
	a.MemTotal = dbItem.MemTotal
	a.ExtraInfo = dbItem.ExtraInfo
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
}

func NewHostCollection(t *tool.Tool) *HostCollection {
	c := new(HostCollection)
	c.collection = newCollectionBuilder[*Host]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_HOST_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Host { return new(metadbmodel.Host) }).
		withCacheItemFactory(func() *Host { return new(Host) }).
		build()
	return c
}

type HostCollection struct {
	collection[*Host, *metadbmodel.Host]
}
