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

// LANIP defines cache data structure.
type LANIP struct {
	lcuuid       string
	id           int
	ip           string
	vInterfaceID int
}

func (t *LANIP) IsValid() bool {
	return t.lcuuid != ""
}

func (t *LANIP) Lcuuid() string {
	return t.lcuuid
}

func (t *LANIP) ID() int {
	return t.id
}

func (t *LANIP) IP() string {
	return t.ip
}

func (t *LANIP) VInterfaceID() int {
	return t.vInterfaceID
}

func (t *LANIP) reset(dbItem *metadbmodel.LANIP, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.ip = dbItem.IP
	t.vInterfaceID = dbItem.VInterfaceID
}

func NewLANIPCollection(t *Tool) *LANIPCollection {
	c := new(LANIPCollection)
	c.resetExt()
	c.collection = newCollectionBuilder[*LANIP]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LANIP { return new(metadbmodel.LANIP) }).
		withCacheItemFactory(func() *LANIP { return new(LANIP) }).
		withExtender(c).
		build()
	return c
}

// LANIPCollection defines a collection that maps individual fields to the LANIP cache data structure.
type LANIPCollection struct {
	collection[*LANIP, *metadbmodel.LANIP]
	LANIPCollectionExt
}
