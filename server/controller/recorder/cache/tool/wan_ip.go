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

// WANIP defines cache data structure.
type WANIP struct {
	lcuuid       string
	id           int
	ip           string
	vInterfaceID int
}

func (t *WANIP) IsValid() bool {
	return t.lcuuid != ""
}

func (t *WANIP) Lcuuid() string {
	return t.lcuuid
}

func (t *WANIP) ID() int {
	return t.id
}

func (t *WANIP) IP() string {
	return t.ip
}

func (t *WANIP) VInterfaceID() int {
	return t.vInterfaceID
}

func (t *WANIP) reset(dbItem *metadbmodel.WANIP, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.ip = dbItem.IP
	t.vInterfaceID = dbItem.VInterfaceID
}

func NewWANIPCollection(t *Tool) *WANIPCollection {
	c := new(WANIPCollection)
	c.resetExt()
	c.collection = newCollectionBuilder[*WANIP]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.WANIP { return new(metadbmodel.WANIP) }).
		withCacheItemFactory(func() *WANIP { return new(WANIP) }).
		withExtender(c).
		build()
	return c
}

// WANIPCollection defines a collection that maps individual fields to the WANIP cache data structure.
type WANIPCollection struct {
	collection[*WANIP, *metadbmodel.WANIP]
	WANIPCollectionExt
}
