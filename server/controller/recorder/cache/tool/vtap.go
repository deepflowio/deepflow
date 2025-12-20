/*
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

package tool

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// VTap defines cache data structure.
type VTap struct {
	id             int
	lcuuid         string
	name           string
	aType          int
	launchServerID int
}

func (t *VTap) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VTap) ID() int {
	return t.id
}

func (t *VTap) Lcuuid() string {
	return t.lcuuid
}

func (t *VTap) Name() string {
	return t.name
}

func (t *VTap) Type() int {
	return t.aType
}

func (t *VTap) LaunchServerID() int {
	return t.launchServerID
}

func (t *VTap) reset(dbItem *metadbmodel.VTap, tool *Tool) {
	t.id = dbItem.ID
	t.lcuuid = dbItem.Lcuuid
	t.name = dbItem.Name
	t.aType = dbItem.Type
	t.launchServerID = dbItem.LaunchServerID
}

func NewVTapCollection(t *Tool) *VTapCollection {
	c := new(VTapCollection)
	c.collection = newCollectionBuilder[*VTap]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VTAP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VTap { return new(metadbmodel.VTap) }).
		withCacheItemFactory(func() *VTap { return new(VTap) }).
		build()
	return c
}

// VTapCollection defines a collection that maps individual fields to the VTap cache data structure.
type VTapCollection struct {
	collection[*VTap, *metadbmodel.VTap]
}
