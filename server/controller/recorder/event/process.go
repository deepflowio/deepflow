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
	"fmt"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Process struct {
	EventManagerBase
	deviceType int
}

func NewProcess(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *Process {
	mng := &Process{
		EventManagerBase{
			resourceType: "process",
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.PROCESS_INSTANCE_TYPE,
	}
	return mng
}

func (p *Process) ProduceByAdd(items []*mysql.Process) {
	processData, err := resource.GetProcessData(items)
	if err != nil {
		log.Error(err)
	}
	var opts []eventapi.TagFieldOption
	for _, item := range items {
		description := fmt.Sprintf("agent %s report process %s cmdline %s",
			processData[item.ID].VTapName, item.ProcessName, item.CommandLine)

		switch t := processData[item.ID].ResourceType; t {
		case common.VIF_DEVICE_TYPE_POD:
			opts = append(opts, eventapi.TagPodID(processData[item.ID].ResourceID))
		case common.VIF_DEVICE_TYPE_POD_NODE:
			opts = append(opts, eventapi.TagPodNodeID(processData[item.ID].ResourceID))
		case common.VIF_DEVICE_TYPE_VM:
			opts = append(opts, eventapi.TagL3DeviceID(processData[item.ID].ResourceID))
			opts = append(opts, eventapi.TagL3DeviceType(processData[item.ID].ResourceType))
		default:
			log.Error("cannot support type: %s", t)
		}
		opts = append(opts, eventapi.TagDescription(description))

		p.createProcessAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (p *Process) ProduceByUpdate(cloudItem *cloudmodel.Process, diffBase *cache.Process) {
}

func (p *Process) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		processInfo, exists := p.ToolDataSet.GetProcessInfoByLcuuid(lcuuid)
		if !exists {
			log.Errorf("process info not fount, lcuuid: %s", lcuuid)
		} else {
			id = processInfo.ID
			name = processInfo.Name
		}

		p.createProcessAndEnqueue(
			lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_DELETE,
			name,
			p.deviceType,
			id,
		)
	}
}
