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

// LBListener defines cache data structure.
type LBListener struct {
	lcuuid string
	id     int
	name   string
	lbID   int
}

func (t *LBListener) IsValid() bool {
	return t.lcuuid != ""
}

func (t *LBListener) Lcuuid() string {
	return t.lcuuid
}

func (t *LBListener) ID() int {
	return t.id
}

func (t *LBListener) Name() string {
	return t.name
}

func (t *LBListener) LBID() int {
	return t.lbID
}

func (t *LBListener) reset(dbItem *metadbmodel.LBListener, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.lbID = dbItem.LBID
}

func NewLBListenerCollection(t *Tool) *LBListenerCollection {
	c := new(LBListenerCollection)
	c.collection = newCollectionBuilder[*LBListener]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LBListener { return new(metadbmodel.LBListener) }).
		withCacheItemFactory(func() *LBListener { return new(LBListener) }).
		build()
	return c
}

// LBListenerCollection defines a collection that maps individual fields to the LBListener cache data structure.
type LBListenerCollection struct {
	collection[*LBListener, *metadbmodel.LBListener]
}
