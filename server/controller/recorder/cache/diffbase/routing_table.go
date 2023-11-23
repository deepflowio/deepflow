/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddRoutingTable(dbItem *mysql.RoutingTable, seq int) {
	b.RoutingTables[dbItem.Lcuuid] = &RoutingTable{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Destination: dbItem.Destination,
		Nexthop:     dbItem.Nexthop,
		NexthopType: dbItem.NexthopType,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, b.RoutingTables[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteRoutingTable(lcuuid string) {
	delete(b.RoutingTables, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, lcuuid))
}

type RoutingTable struct {
	DiffBase
	Destination string `json:"destination"`
	Nexthop     string `json:"nexthop"`
	NexthopType string `json:"nexthop_type"`
}

func (r *RoutingTable) Update(cloudItem *cloudmodel.RoutingTable) {
	r.Destination = cloudItem.Destination
	r.Nexthop = cloudItem.Nexthop
	r.NexthopType = cloudItem.NexthopType
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, r))
}
