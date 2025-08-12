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

package pubsub

const (
	// TopicPlatformChanged is the topic for any change of the platform, including resource added, updated, deleted.
	// The subscriber should implement the AnyChangedSubscriber interface if it subscribes this topic.
	TopicPlatformChanged = iota
	// TopicResourceBatchAddedFull is the topic for resource batch added notification, including metadb and specific data.
	// The subscriber should implement the ResourceBatchAddedSubscriber interface if it subscribes this topic.
	TopicResourceBatchAddedFull
	// TopicResourceBatchAddedMetadbItems is the topic for resource batch added notification, only including metadb data.
	// The subscriber should implement the ResourceBatchAddedSubscriber interface if it subscribes this topic.
	TopicResourceBatchAddedMetadbItems
	// TopicResourceUpdatedFields is the topic for resource updated notification, only including updated fields data.
	// The subscriber should implement the ResourceUpdatedSubscriber interface if it subscribes this topic.
	TopicResourceUpdatedFields
	// TopicResourceUpdatedFull is the topic for resource updated notification, including metadb, updated fields, and other specific data.
	// The subscriber should implement the ResourceUpdatedSubscriber interface if it subscribes this topic.
	TopicResourceUpdatedFull
	// TopicResourceBatchDeletedLcuuids is the topic for resource batch deleted notification, only including lcuuid data.
	// The subscriber should implement the ResourceBatchDeletedSubscriber interface if it subscribes this topic.
	TopicResourceBatchDeletedLcuuids
	// TopicResourceBatchDeletedMetadbItems is the topic for resource batch deleted notification, only including metadb data.
	// The subscriber should implement the ResourceBatchDeletedSubscriber interface if it subscribes this topic.
	TopicResourceBatchDeletedMetadbItems
	// TopicResourceBatchDeletedFull is the topic for resource batch deleted notification, including metadb and specific data.
	// The subscriber should implement the ResourceBatchDeletedSubscriber interface if it subscribes this topic.
	TopicResourceBatchDeletedFull
)

// SubscriptionSpec encapsulates subscription specification/configuration for subscribers
type SubscriptionSpec struct {
	// PubSubType is the publish-subscribe center type, used to find the corresponding publish-subscribe center
	PubSubType string
	// PublisherDomainUUID specifies the publisher domain UUID to distinguish different publishers in the publish center.
	// In current version, one domain has only one publisher. Empty value means subscribing to all publishers.
	PublisherDomainUUID string
	// Topic specifies the specific topic type to subscribe to (e.g., TopicPlatformChanged, TopicResourceBatchAddedFull, etc.)
	Topic int
}

type SubscriptionSpecOption func(st *SubscriptionSpec)

func SubscriptionSpecOptionDomain(domain string) SubscriptionSpecOption {
	return func(st *SubscriptionSpec) {
		st.PublisherDomainUUID = domain
	}
}

// NewSubscriptionSpec creates a new subscription specification
func NewSubscriptionSpec(pubSubType string, topic int, options ...SubscriptionSpecOption) *SubscriptionSpec {
	st := &SubscriptionSpec{
		PubSubType: pubSubType,
		Topic:      topic,
	}
	for _, option := range options {
		option(st)
	}
	return st
}

// Matches checks if the subscription specification matches the publishing content
func (ss SubscriptionSpec) Matches(domainUUID string) bool {
	if ss.PublisherDomainUUID == "" {
		return true
	}
	return ss.PublisherDomainUUID == domainUUID
}
