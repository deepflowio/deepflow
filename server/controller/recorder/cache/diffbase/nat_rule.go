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

type NATRule struct {
	ResourceBase
}

func (a *NATRule) reset(dbItem *metadbmodel.NATRule, tool *tool.Tool) {
}

func NewNATRuleCollection(t *tool.Tool) *NATRuleCollection {
	c := new(NATRuleCollection)
	c.collection = newCollectionBuilder[*NATRule]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.NATRule { return new(metadbmodel.NATRule) }).
		withCacheItemFactory(func() *NATRule { return new(NATRule) }).
		build()
	return c
}

type NATRuleCollection struct {
	collection[*NATRule, *metadbmodel.NATRule]
}
