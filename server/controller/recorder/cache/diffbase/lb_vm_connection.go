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

type LBVMConnection struct {
	ResourceBase
}

func (a *LBVMConnection) reset(dbItem *metadbmodel.LBVMConnection, tool *tool.Tool) {
}

func NewLBVMConnectionCollection(t *tool.Tool) *LBVMConnectionCollection {
	c := new(LBVMConnectionCollection)
	c.collection = newCollectionBuilder[*LBVMConnection]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LBVMConnection { return new(metadbmodel.LBVMConnection) }).
		withCacheItemFactory(func() *LBVMConnection { return new(LBVMConnection) }).
		build()
	return c
}

type LBVMConnectionCollection struct {
	collection[*LBVMConnection, *metadbmodel.LBVMConnection]
}
