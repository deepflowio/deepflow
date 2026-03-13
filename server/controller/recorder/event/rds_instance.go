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

type RDSInstance struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
}

func NewRDSInstance(q *queue.OverwriteQueue) *RDSInstance {
	mng := &RDSInstance{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN),
		ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (r *RDSInstance) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.RDSInstance) {
		var opts []eventapi.TagFieldOption
		rdsItem := md.GetToolDataSet().RdsInstance().GetById(item.ID)
		if !rdsItem.IsValid() {
			log.Errorf("rds_instance(id=%d) not found", item.ID, md.LogPrefixes)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(rdsItem.AzId()),
				eventapi.TagRegionID(rdsItem.RegionId()),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(r.deviceType),
			eventapi.TagL3DeviceID(item.ID),
		}...)

		r.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			r.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (r *RDSInstance) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.RDSInstance) {
		r.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, r.deviceType, item.ID)
	}
}
