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

package event

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type NATGateway struct {
	EventManagerBase
	deviceType int
}

func NewNATGateway(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *NATGateway {
	mng := &NATGateway{
		EventManagerBase{
			resourceType: ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY,
	}
	return mng
}

func (n *NATGateway) ProduceByAdd(items []*mysql.NATGateway) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := n.ToolDataSet.GetNATGatewayInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(n.deviceType),
			eventapi.TagL3DeviceID(item.ID),
		}...)

		n.createAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			n.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (n *NATGateway) ProduceByUpdate(cloudItem *cloudmodel.NATGateway, diffBase *diffbase.NATGateway) {
}

func (n *NATGateway) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := n.ToolDataSet.GetNATGatewayIDByLcuuid(lcuuid)
		if ok {
			var err error
			name, err = n.ToolDataSet.GetNATGatewayNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(n.resourceType, lcuuid), err)
			}
		} else {
			log.Error(nameByIDNotFound(n.resourceType, id))
		}

		n.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, n.deviceType, id)
	}
}
