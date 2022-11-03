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
	"errors"
	"fmt"

	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

var (
	VMStateToString = map[int]string{
		common.VM_STATE_RUNNING:   "running",
		common.VM_STATE_STOPPED:   "stopped",
		common.VM_STATE_EXCEPTION: "exception",
	}
)

type VM struct {
	EventManager[cloudmodel.VM, mysql.VM, *cache.VM]
}

func NewVM(toolDS cache.ToolDataSet, eq *queue.OverwriteQueue) *VM {
	mng := &VM{
		EventManager[cloudmodel.VM, mysql.VM, *cache.VM]{
			resourceType: RESOURCE_TYPE_VM_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
	}
	return mng
}

func (v *VM) ProduceByAdd(items []*mysql.VM) {
	for _, item := range items {
		v.createAndPutEvent(
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			common.VIF_DEVICE_TYPE_VM,
			item.ID,
			item.Name,
			"",
		)
	}
}

func (v *VM) ProduceByUpdate(cloudItem *cloudmodel.VM, diffBase *cache.VM) {
	if diffBase.LaunchServer != cloudItem.LaunchServer {
		v.migrate(cloudItem, diffBase)
	}
	if diffBase.State != cloudItem.State {
		v.updateState(cloudItem, diffBase)
	}
}

func (v *VM) migrate(cloudItem *cloudmodel.VM, diffBase *cache.VM) {
	id, name, err := getVMIDAndNameByLcuuid(v, cloudItem.Lcuuid)
	if err != nil {
		log.Error(err)
	}

	v.createAndPutEvent(
		eventapi.RESOURCE_EVENT_TYPE_MIGRATE,
		common.VIF_DEVICE_TYPE_VM,
		id,
		name,
		fmt.Sprintf("%s,%s", diffBase.LaunchServer, cloudItem.LaunchServer),
	)
}

func (v *VM) updateState(cloudItem *cloudmodel.VM, diffBase *cache.VM) {
	id, name, err := getVMIDAndNameByLcuuid(v, cloudItem.Lcuuid)
	if err != nil {
		log.Error(err)
	}

	v.createAndPutEvent(
		eventapi.RESOURCE_EVENT_TYPE_UPDATE_STATE,
		common.VIF_DEVICE_TYPE_VM,
		id,
		name,
		fmt.Sprintf("%s,%s", VMStateToString[diffBase.State], VMStateToString[cloudItem.State]),
	)
}

func (v *VM) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		id, name, err := getVMIDAndNameByLcuuid(v, lcuuid)
		if err != nil {
			log.Error(err)
		}

		v.createAndPutEvent(
			eventapi.RESOURCE_EVENT_TYPE_DELETE,
			common.VIF_DEVICE_TYPE_VM,
			id,
			name,
			"",
		)
	}
}

func getVMIDAndNameByLcuuid(v *VM, lcuuid string) (int, string, error) {
	id, ok := v.ToolDataSet.GetVMIDByLcuuid(lcuuid)
	if !ok {
		return 0, "", errors.New(nameByIDNotFound(v.resourceType, id))
	}
	name, ok := v.ToolDataSet.GetVMNameByID(id)
	if !ok {
		return 0, "", errors.New(idByLcuuidNotFound(v.resourceType, lcuuid))
	}

	return id, name, nil
}
