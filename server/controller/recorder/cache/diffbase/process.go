/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddProcess(dbItem *mysql.Process, seq int) {
	b.Process[dbItem.Lcuuid] = &Process{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:        dbItem.Name,
		OSAPPTags:   dbItem.OSAPPTags,
		ContainerID: dbItem.ContainerID,
		DeviceType:  dbItem.DeviceType,
		DeviceID:    dbItem.DeviceID,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, b.Process[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteProcess(lcuuid string) {
	delete(b.Process, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, lcuuid))
}

type Process struct {
	DiffBase
	Name        string `json:"name"`
	OSAPPTags   string `json:"os_app_tags"`
	ContainerID string `json:"container_id"`
	DeviceType  int    `json:"device_type"`
	DeviceID    int    `json:"device_id"`
}

func (p *Process) Update(cloudItem *cloudmodel.Process, toolDataSet *tool.DataSet) {
	p.Name = cloudItem.Name
	p.OSAPPTags = cloudItem.OSAPPTags
	p.ContainerID = cloudItem.ContainerID
	deviceType, deviceID := toolDataSet.GetProcessDeviceTypeAndID(cloudItem.ContainerID, cloudItem.VTapID)
	if p.DeviceType != deviceType || p.DeviceID != deviceID {
		p.DeviceType = deviceType
		p.DeviceID = deviceID
	}
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, p))
}
