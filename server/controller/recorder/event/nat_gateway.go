/*
 * Copyright (c) 2022 Yunshan Networks
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

package event

import (
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type NATGateway struct {
	EventManager[cloudmodel.NATGateway, mysql.NATGateway, *cache.NATGateway]
	deviceType int
}

func NewNATGateway(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *NATGateway {
	mng := &NATGateway{
		EventManager[cloudmodel.NATGateway, mysql.NATGateway, *cache.NATGateway]{
			resourceType: RESOURCE_TYPE_NAT_GATEWAY_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_NAT_GATEWAY,
	}
	return mng
}

func (n *NATGateway) ProduceByAdd(items []*mysql.NATGateway) {
	for _, item := range items {
		n.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, n.deviceType, item.ID, item.Name, "", []uint32{}, []string{})
	}
}

func (n *NATGateway) ProduceByUpdate(cloudItem *cloudmodel.NATGateway, diffBase *cache.NATGateway) {
}

func (n *NATGateway) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := n.ToolDataSet.GetNATGatewayIDByLcuuid(lcuuid)
		if ok {
			name, ok = n.ToolDataSet.GetNATGatewayNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(n.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(n.resourceType, id))
		}

		n.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, n.deviceType, id, name, "", []uint32{}, []string{})
	}
}
