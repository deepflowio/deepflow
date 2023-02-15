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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type SubDomain struct {
	cache         *cache.Cache
	eventProducer *event.SubDomain
}

func NewSubDomain(domainLcuuid, subDomainLcuuid string, c *cache.Cache, eq *queue.OverwriteQueue) *SubDomain {
	return &SubDomain{
		cache:         c,
		eventProducer: event.NewSubDomain(domainLcuuid, subDomainLcuuid, &c.ToolDataSet, eq),
	}
}

func (p *SubDomain) OnUpdatersCompeleted() {
	p.eventProducer.ProduceFromMySQL()
}
