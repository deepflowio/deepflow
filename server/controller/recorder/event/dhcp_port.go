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

type DHCPPort struct {
	EventManager[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]
	deviceType int
}

func NewDHCPPort(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *DHCPPort {
	mng := &DHCPPort{
		EventManager[cloudmodel.DHCPPort, mysql.DHCPPort, *cache.DHCPPort]{
			resourceType: RESOURCE_TYPE_DHCP_PORT_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_DHCP_PORT,
	}
	return mng
}

func (p *DHCPPort) ProduceByAdd(items []*mysql.DHCPPort) {
	for _, item := range items {
		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, p.deviceType, item.ID, item.Name, "", []uint32{}, []string{})
	}
}

func (p *DHCPPort) ProduceByUpdate(cloudItem *cloudmodel.DHCPPort, diffBase *cache.DHCPPort) {
}

func (p *DHCPPort) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetDHCPPortIDByLcuuid(lcuuid)
		if ok {
			name, ok = p.ToolDataSet.GetDHCPPortNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(p.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, p.deviceType, id, name, "", []uint32{}, []string{})
	}
}
