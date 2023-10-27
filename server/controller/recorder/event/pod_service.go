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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodService struct {
	EventManagerBase
	deviceType int
}

func NewPodService(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *PodService {
	mng := &PodService{
		EventManagerBase{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE,
	}
	return mng
}

func (p *PodService) ProduceByAdd(items []*mysql.PodService) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := p.ToolDataSet.GetPodServiceInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagPodServiceID(item.ID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(p.deviceType),
			eventapi.TagL3DeviceID(item.ID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagPodNSID(item.PodNamespaceID),
		}...)

		p.createAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (p *PodService) ProduceByUpdate(cloudItem *cloudmodel.PodService, diffBase *cache.PodService) {
}

func (p *PodService) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodServiceIDByLcuuid(lcuuid)
		if ok {
			var err error
			name, err = p.ToolDataSet.GetPodServiceNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(p.resourceType, lcuuid), err)
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, p.deviceType, id)
	}
}
