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

type NATGateway struct {
	ResourceBase
	Name         string
	FloatingIPs  string
	RegionLcuuid string
}

func (a *NATGateway) reset(dbItem *metadbmodel.NATGateway, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.FloatingIPs = dbItem.FloatingIPs
	a.RegionLcuuid = dbItem.Region
}

func NewNATGatewayCollection(t *tool.Tool) *NATGatewayCollection {
	c := new(NATGatewayCollection)
	c.collection = newCollectionBuilder[*NATGateway]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.NATGateway { return new(metadbmodel.NATGateway) }).
		withCacheItemFactory(func() *NATGateway { return new(NATGateway) }).
		build()
	return c
}

type NATGatewayCollection struct {
	collection[*NATGateway, *metadbmodel.NATGateway]
}
