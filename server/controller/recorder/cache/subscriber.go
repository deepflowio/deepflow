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

package cache

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// Subscriber is the interface that cache subscribers must implement.
type Subscriber interface {
	pubsub.Subscriber

	getResourceType() string
}

// subscriberComponent is the non-generic base for cache subscribers.
// It uses diffbase.CollectionOperator and tool.CollectionOperator interfaces
// instead of the previous 10 generic type parameters (MAPT, MAT, MUPT, MUT, MDPT, MDT, MPT, MT, DT, TT).
type subscriberComponent struct {
	resourceType string
	md           *common.Metadata

	diffBase diffbase.CollectionOperator
	tool     tool.CollectionOperator

	topics []int
}

func (c *subscriberComponent) getResourceType() string {
	return c.resourceType
}

func (c *subscriberComponent) Subscribe() {
	if c.md == nil {
		return
	}
	// Default topics
	if len(c.topics) == 0 {
		c.topics = []int{
			pubsub.TopicResourceBatchAddedFull,
			pubsub.TopicResourceUpdatedFull,
			pubsub.TopicResourceBatchDeletedFull,
		}
	}
	var specs []*pubsub.SubscriptionSpec
	for _, topic := range c.topics {
		specs = append(specs, pubsub.NewSubscriptionSpec(c.resourceType, topic, pubsub.SubscriptionSpecOptionDomain(c.md.GetDomainLcuuid())))
	}
	pubsub.Subscribe(
		c,
		specs...,
	)
}

// OnResourceBatchAdded implements pubsub.ResourceBatchAddedSubscriber.
// msg is a types.Added when subscribed to TopicResourceBatchAddedFull.
func (c *subscriberComponent) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	added := msg.(types.Added)
	c.onBatchAdded(0, added.GetMetadbItems())
}

// onBatchAdded is a shared helper for both pubsub subscription and refresh loading.
func (c *subscriberComponent) onBatchAdded(seq int, dbItems interface{}) {
	if c.diffBase != nil {
		c.diffBase.AddItems(seq, dbItems)
	}
	if c.tool != nil {
		c.tool.AddItems(dbItems)
	}
}

// OnResourceUpdated implements pubsub.ResourceUpdatedSubscriber.
// msg is a types.Updated when subscribed to TopicResourceUpdatedFull.
func (c *subscriberComponent) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updated := msg.(types.Updated)
	dbItem := updated.GetNewMetadbItem()
	if c.diffBase != nil {
		c.diffBase.UpdateItem(dbItem)
	}
	if c.tool != nil {
		c.tool.UpdateItem(dbItem)
	}
}

// OnResourceBatchDeleted implements pubsub.ResourceBatchDeletedSubscriber.
// msg is a types.Deleted when subscribed to TopicResourceBatchDeletedFull.
func (c *subscriberComponent) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	deleted := msg.(types.Deleted)
	if c.diffBase != nil {
		for _, lcuuid := range deleted.GetLcuuids() {
			c.diffBase.DeleteByLcuuid(lcuuid)
		}
	}
	if c.tool != nil {
		c.tool.DeleteItems(deleted.GetMetadbItems())
	}
}
