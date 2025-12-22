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

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.pubsub")

type PubSub interface {
	Subscribe(subscriber interface{}, spec *SubscriptionSpec)
}

type PubSubComponent struct {
	pubSubType            string
	topicToSubscriberInfo map[int][]*SubscriberInfo
}

func newPubSubComponent(pubsubType string) PubSubComponent {
	return PubSubComponent{
		pubSubType:            pubsubType,
		topicToSubscriberInfo: make(map[int][]*SubscriberInfo),
	}
}

func (p *PubSubComponent) Subscribe(subscriber interface{}, spec *SubscriptionSpec) {
	if _, exists := p.topicToSubscriberInfo[spec.Topic]; !exists {
		p.topicToSubscriberInfo[spec.Topic] = []*SubscriberInfo{}
	}
	p.topicToSubscriberInfo[spec.Topic] = append(p.topicToSubscriberInfo[spec.Topic], newSubscriberInfo(subscriber, spec))
}

// AnyChangePubSub interface for a whole platform such as domain, subdomain
type AnyChangePubSub interface {
	PubSub
	PublishChange(*message.Metadata) // publish any change of a platform, only notify the fact that the cloud platform has been changed, without specific changed data.
}

func newAnyChangePubSub(pubSubType string) AnyChangePubSub {
	return &AnyChangePubSubComponent{
		PubSubComponent: newPubSubComponent(pubSubType),
	}
}

type AnyChangePubSubComponent struct {
	PubSubComponent
}

func (p *AnyChangePubSubComponent) PublishChange(md *message.Metadata) {
	for topic, infos := range p.topicToSubscriberInfo {
		for _, info := range infos {
			if !info.GetSubscriptionSpec().Matches(md.GetDomainLcuuid()) {
				continue
			}
			if topic == TopicPlatformChanged {
				info.GetSubscriber().(AnyChangedSubscriber).OnAnyChanged(md)
			}
		}
	}
}

// ResourcePubSub interface for a specific resource
type ResourcePubSub interface {
	PubSub
	PublishBatchAdded(*message.Metadata, types.Added)     // publish resource batch added notification, including specific data
	PublishUpdated(*message.Metadata, types.Updated)      // publish resource updated notification, including specific data
	PublishBatchDeleted(*message.Metadata, types.Deleted) // publish resource batch deleted notification, including specific data
}

func newResourcePubSub(pubSubType string) ResourcePubSub {
	return &ResourcePubSubComponent{
		resourceType:    rscPubSubTypeToResourceType[pubSubType],
		PubSubComponent: newPubSubComponent(pubSubType),
	}
}

type ResourcePubSubComponent struct {
	resourceType string
	PubSubComponent
}

func (p *ResourcePubSubComponent) PublishBatchAdded(md *message.Metadata, msg types.Added) {
	// TODO better log
	log.Debugf("publish add %#v, %#v", md, msg)
	for topic, infos := range p.topicToSubscriberInfo {
		for _, info := range infos {
			if !info.GetSubscriptionSpec().Matches(md.GetDomainLcuuid()) {
				continue
			}

			if topic == TopicResourceBatchAddedMetadbItems {
				info.GetSubscriber().(ResourceBatchAddedSubscriber).OnResourceBatchAdded(md, msg.GetMetadbItems())
			}
			if topic == TopicResourceBatchAddedFull {
				info.GetSubscriber().(ResourceBatchAddedSubscriber).OnResourceBatchAdded(md, msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent) PublishUpdated(md *message.Metadata, msg types.Updated) {
	log.Debugf("publish update %#v, %#v", md, msg)
	for topic, infos := range p.topicToSubscriberInfo {
		for _, info := range infos {
			if !info.GetSubscriptionSpec().Matches(md.GetDomainLcuuid()) {
				continue
			}

			if topic == TopicResourceUpdatedFields {
				info.GetSubscriber().(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg.GetFields())
			}
			if topic == TopicResourceUpdatedFull {
				info.GetSubscriber().(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent) PublishBatchDeleted(md *message.Metadata, msg types.Deleted) {
	log.Debugf("publish delete %#v, %#v", md, msg)
	for topic, infos := range p.topicToSubscriberInfo {
		for _, info := range infos {
			if !info.GetSubscriptionSpec().Matches(md.GetDomainLcuuid()) {
				continue
			}

			if topic == TopicResourceBatchDeletedLcuuids {
				info.GetSubscriber().(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg.GetLcuuids())
			}
			if topic == TopicResourceBatchDeletedMetadbItems {
				info.GetSubscriber().(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg.GetMetadbItems())
			}
			if topic == TopicResourceBatchDeletedFull {
				info.GetSubscriber().(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg)
			}
		}
	}
}
