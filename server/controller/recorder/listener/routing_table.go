/*
 * Copyright (c) 2023 Yunshan Networks
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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type RoutingTable struct {
	cache *cache.Cache
}

func NewRoutingTable(c *cache.Cache) *RoutingTable {
	listener := &RoutingTable{
		cache: c,
	}
	return listener
}

func (rt *RoutingTable) OnUpdaterAdded(addedDBItems []*mysql.RoutingTable) {
	rt.cache.AddRoutingTables(addedDBItems)
}

func (rt *RoutingTable) OnUpdaterUpdated(cloudItem *cloudmodel.RoutingTable, diffBase *diffbase.RoutingTable) {
	diffBase.Update(cloudItem)
}

func (rt *RoutingTable) OnUpdaterDeleted(lcuuids []string) {
	rt.cache.DeleteRoutingTables(lcuuids)
}
