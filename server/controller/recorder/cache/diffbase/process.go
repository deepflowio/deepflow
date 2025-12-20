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

type Process struct {
	ResourceBase
	Name        string
	OSAPPTags   string
	ContainerID string
	DeviceType  int
	DeviceID    int
}

func (a *Process) reset(dbItem *metadbmodel.Process, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.OSAPPTags = dbItem.OSAPPTags
	a.ContainerID = dbItem.ContainerID
	a.DeviceType = dbItem.DeviceType
	a.DeviceID = dbItem.DeviceID
}

func NewProcessCollection(t *tool.Tool) *ProcessCollection {
	c := new(ProcessCollection)
	c.collection = newCollectionBuilder[*Process]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Process { return new(metadbmodel.Process) }).
		withCacheItemFactory(func() *Process { return new(Process) }).
		build()
	return c
}

type ProcessCollection struct {
	collection[*Process, *metadbmodel.Process]
}
