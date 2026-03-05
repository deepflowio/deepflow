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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type NATGateway struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
}

func NewNATGateway(q *queue.OverwriteQueue) *NATGateway {
	mng := &NATGateway{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN),
		ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (n *NATGateway) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.NATGateway) {
		var opts []eventapi.TagFieldOption
		ngItem := md.GetToolDataSet().NatGateway().GetById(item.ID)
		if !ngItem.IsValid() {
			log.Errorf("nat_gateway(id=%d) not found", item.ID, md.LogPrefixes)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(ngItem.AzId()),
				eventapi.TagRegionID(ngItem.RegionId()),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(n.deviceType),
			eventapi.TagL3DeviceID(item.ID),
		}...)

		n.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			n.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (n *NATGateway) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.NATGateway) {
		n.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, n.deviceType, item.ID)
	}
}
