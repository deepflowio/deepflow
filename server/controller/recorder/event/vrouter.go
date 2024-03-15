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

type VRouter struct {
	EventManagerBase
	deviceType int
}

func NewVRouter(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *VRouter {
	mng := &VRouter{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_VROUTER_EN,
			toolDS,
			eq,
		),
		ctrlrcommon.VIF_DEVICE_TYPE_VROUTER,
	}
	return mng
}

func (r *VRouter) ProduceByAdd(items []*mysql.VRouter) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := r.ToolDataSet.GetVRouterInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagRegionID(info.RegionID),
			}...)
		}

		if item.GWLaunchServer != "" {
			hostID, ok := r.ToolDataSet.GetHostIDByIP(item.GWLaunchServer)
			if !ok {
				log.Error(idByIPNotFound(ctrlrcommon.RESOURCE_TYPE_HOST_EN, item.GWLaunchServer))
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagHostID(hostID),
				}...)
			}
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

func (r *VRouter) ProduceByUpdate(cloudItem *cloudmodel.VRouter, diffBase *diffbase.VRouter) {
}

func (r *VRouter) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := r.ToolDataSet.GetVRouterIDByLcuuid(lcuuid)
		if !ok {
			log.Error(nameByIDNotFound(r.resourceType, id))
		} else {
			var err error
			name, err = r.ToolDataSet.GetVRouterNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(r.resourceType, lcuuid), err)
			}
		}

		r.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, r.deviceType, id)
	}
}
