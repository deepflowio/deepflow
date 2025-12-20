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

// PodIngressRule defines cache data structure.
type PodIngressRule struct {
	lcuuid string
	id     int
	name   string
}

func (t *PodIngressRule) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodIngressRule) Lcuuid() string {
	return t.lcuuid
}

func (t *PodIngressRule) ID() int {
	return t.id
}

func (t *PodIngressRule) Name() string {
	return t.name
}

func (t *PodIngressRule) reset(dbItem *metadbmodel.PodIngressRule, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
}

func NewPodIngressRuleCollection(t *Tool) *PodIngressRuleCollection {
	c := new(PodIngressRuleCollection)
	c.collection = newCollectionBuilder[*PodIngressRule]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodIngressRule { return new(metadbmodel.PodIngressRule) }).
		withCacheItemFactory(func() *PodIngressRule { return new(PodIngressRule) }).
		build()
	return c
}

// PodIngressRuleCollection defines a collection that maps individual fields to the PodIngressRule cache data structure.
type PodIngressRuleCollection struct {
	collection[*PodIngressRule, *metadbmodel.PodIngressRule]
}
