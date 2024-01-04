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
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("recorder/listener")

type WholeDomain struct {
	cache         *cache.Cache
	eventProducer *event.Domain
}

func NewWholeDomain(domainLcuuid string, c *cache.Cache, eq *queue.OverwriteQueue) *WholeDomain {
	listener := &WholeDomain{
		cache:         c,
		eventProducer: event.NewDomain(domainLcuuid, c.ToolDataSet, eq),
	}
	return listener
}

func (p *WholeDomain) OnUpdatersCompleted() {
	p.eventProducer.ProduceFromMySQL()
}
