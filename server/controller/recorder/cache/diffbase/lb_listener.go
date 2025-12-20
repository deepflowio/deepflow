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

type LBListener struct {
	ResourceBase
	Name     string
	IPs      string
	SNATIPs  string
	Port     int
	Protocol string
}

func (a *LBListener) reset(dbItem *metadbmodel.LBListener, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.IPs = dbItem.IPs
	a.SNATIPs = dbItem.SNATIPs
	a.Port = dbItem.Port
	a.Protocol = dbItem.Protocol
}

func NewLBListenerCollection(t *tool.Tool) *LBListenerCollection {
	c := new(LBListenerCollection)
	c.collection = newCollectionBuilder[*LBListener]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LBListener { return new(metadbmodel.LBListener) }).
		withCacheItemFactory(func() *LBListener { return new(LBListener) }).
		build()
	return c
}

type LBListenerCollection struct {
	collection[*LBListener, *metadbmodel.LBListener]
}
