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

type VMPodNodeConnection struct {
	ResourceBase
	SubDomainLcuuid string
}

func (a *VMPodNodeConnection) reset(dbItem *metadbmodel.VMPodNodeConnection, tool *tool.Tool) {
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewVMPodNodeConnectionCollection(t *tool.Tool) *VMPodNodeConnectionCollection {
	c := new(VMPodNodeConnectionCollection)
	c.collection = newCollectionBuilder[*VMPodNodeConnection]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VMPodNodeConnection { return new(metadbmodel.VMPodNodeConnection) }).
		withCacheItemFactory(func() *VMPodNodeConnection { return new(VMPodNodeConnection) }).
		build()
	return c
}

type VMPodNodeConnectionCollection struct {
	collection[*VMPodNodeConnection, *metadbmodel.VMPodNodeConnection]
}
