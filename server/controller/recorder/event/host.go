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

type Host struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
}

func NewHost(q *queue.OverwriteQueue) *Host {
	mng := &Host{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_HOST_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_HOST_EN),
		ctrlrcommon.VIF_DEVICE_TYPE_HOST,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (h *Host) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.Host) {
		var opts []eventapi.TagFieldOption
		info, err := md.GetToolDataSet().GetHostInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagHostID(item.ID),
			eventapi.TagL3DeviceID(item.ID),
			eventapi.TagL3DeviceType(h.deviceType),
		}...)

		h.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			h.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (h *Host) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.Host) {
		h.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, h.deviceType, item.ID)
	}
}
