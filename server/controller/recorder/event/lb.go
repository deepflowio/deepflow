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

type LB struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
}

func NewLB(q *queue.OverwriteQueue) *LB {
	mng := &LB{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_LB_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_LB_EN),
		ctrlrcommon.VIF_DEVICE_TYPE_LB,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (l *LB) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.LB) {
		var opts []eventapi.TagFieldOption
		info, err := md.GetToolDataSet().GetLBInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(l.deviceType),
			eventapi.TagL3DeviceID(item.ID),
		}...)

		l.createAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			l.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (l *LB) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.LB) {
		l.createAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, l.deviceType, item.ID)
	}
}
