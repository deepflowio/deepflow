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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Host struct {
	EventManagerBase
	deviceType int
}

func NewHost(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *Host {
	mng := &Host{
		EventManagerBase{
			resourceType: RESOURCE_TYPE_HOST_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_HOST,
	}
	return mng
}

func (h *Host) ProduceByAdd(items []*mysql.Host) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := h.ToolDataSet.GetHostInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, eventapi.TagHostID(item.ID))

		h.createAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			h.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (h *Host) ProduceByUpdate(cloudItem *cloudmodel.Host, diffBase *cache.Host) {
}

func (h *Host) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var name string
		id, ok := h.ToolDataSet.GetHostIDByLcuuid(lcuuid)
		if !ok {
			log.Error(nameByIDNotFound(h.resourceType, id))
		} else {
			var err error
			name, err = h.ToolDataSet.GetHostNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(h.resourceType, lcuuid), err)
			}
		}

		h.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, h.deviceType, id)
	}
}
