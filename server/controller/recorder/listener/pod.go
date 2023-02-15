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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Pod struct {
	cache         *cache.Cache
	eventProducer *event.Pod
}

func NewPod(c *cache.Cache, eq *queue.OverwriteQueue) *Pod {
	lisener := &Pod{
		cache:         c,
		eventProducer: event.NewPod(&c.ToolDataSet, eq),
	}
	return lisener
}

func (p *Pod) OnUpdaterAdded(addedDBItems []*mysql.Pod) {
	// p.cache.AddPods(addedDBItems)
	p.eventProducer.ProduceByAdd(addedDBItems)
}

func (p *Pod) OnUpdaterUpdated(cloudItem *cloudmodel.Pod, diffBase *cache.Pod) {
	p.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	// diffBase.Update(cloudItem)
	// p.cache.UpdatePod(cloudItem)
}

func (p *Pod) OnUpdaterDeleted(lcuuids []string) {
	p.eventProducer.ProduceByDelete(lcuuids)
	// p.cache.DeletePods(lcuuids)
}
