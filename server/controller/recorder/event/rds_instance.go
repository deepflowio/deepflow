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

package event

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type RDSInstance struct {
	EventManagerBase
	deviceType int
}

func NewRDSInstance(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *RDSInstance {
	return &RDSInstance{
		EventManagerBase{
			resourceType: ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE,
	}
}

func (r *RDSInstance) ProduceByAdd(items []*mysql.RDSInstance) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := r.ToolDataSet.GetRDSInstanceInfoByID(item.ID)
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
			eventapi.TagL3DeviceType(r.deviceType),
			eventapi.TagL3DeviceID(item.ID),
		}...)

		r.createAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			r.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (r *RDSInstance) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := r.ToolDataSet.GetRDSInstanceIDByLcuuid(lcuuid)
		if ok {
			var err error
			name, err = r.ToolDataSet.GetRDSInstanceNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(r.resourceType, lcuuid), err)
			}
		} else {
			log.Error(nameByIDNotFound(r.resourceType, id))
		}

		r.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, r.deviceType, id)
	}
}
