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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type VM struct {
	cache         *cache.Cache
	eventProducer *event.VM
}

func NewVM(c *cache.Cache, eq *queue.OverwriteQueue) *VM {
	listener := &VM{
		cache:         c,
		eventProducer: event.NewVM(c.ToolDataSet, eq),
	}
	return listener
}

func (vm *VM) OnUpdaterAdded(addedDBItems []*mysql.VM) {
	vm.eventProducer.ProduceByAdd(addedDBItems)
	vm.cache.AddVMs(addedDBItems)
}

func (vm *VM) OnUpdaterUpdated(cloudItem *cloudmodel.VM, diffBase *diffbase.VM) {
	vm.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem)
	vm.cache.UpdateVM(cloudItem)
}

func (vm *VM) OnUpdaterDeleted(lcuuids []string) {
	vm.eventProducer.ProduceByDelete(lcuuids)
	vm.cache.DeleteVMs(lcuuids)
}
