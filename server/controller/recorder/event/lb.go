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

type LB struct {
	EventManager[cloudmodel.LB, mysql.LB, *cache.LB]
	deviceType int
}

func NewLB(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *LB {
	mng := &LB{
		EventManager[cloudmodel.LB, mysql.LB, *cache.LB]{
			resourceType: RESOURCE_TYPE_LB_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_LB,
	}
	return mng
}

func (l *LB) ProduceByAdd(items []*mysql.LB) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := l.ToolDataSet.GetLBInfoByID(item.ID)
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

		l.createAndPutEvent(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			l.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (l *LB) ProduceByUpdate(cloudItem *cloudmodel.LB, diffBase *cache.LB) {
}

func (l *LB) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := l.ToolDataSet.GetLBIDByLcuuid(lcuuid)
		if ok {
			var err error
			name, err = l.ToolDataSet.GetLBNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(l.resourceType, lcuuid), err)
			}
		} else {
			log.Error(nameByIDNotFound(l.resourceType, id))
		}

		l.createAndPutEvent(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, l.deviceType, id)
	}
}
