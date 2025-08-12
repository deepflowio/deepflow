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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
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
type ResourcePubSub[
	MAPT constraint.AddPtr[MAT],
	MAT constraint.Add,
	MAAT message.AddAddition,
	MUPT constraint.UpdatePtr[MUT],
	MUT constraint.Update,
	MFUPT constraint.FieldsUpdatePtr[MFUT],
	MFUT constraint.FieldsUpdate,
	MDPT constraint.DeletePtr[MDT],
	MDT constraint.Delete,
	MDAT message.DeleteAddition,
] interface {
	PubSub
	// PublishChange(*message.Metadata)             // publish any change of the resource, only notify the fact that some of the whole resource has been changed, without specific changed data
	PublishBatchAdded(*message.Metadata, MAPT)   // publish resource batch added notification, including specific data
	PublishUpdated(*message.Metadata, MUPT)      // publish resource updated notification, including specific data
	PublishBatchDeleted(*message.Metadata, MDPT) // publish resource batch deleted notification, including specific data
}

type ResourcePubSubComponent[
	MAPT constraint.AddPtr[MAT],
	MAT constraint.Add,
	MAAT message.AddAddition,
	MUPT constraint.UpdatePtr[MUT],
	MUT constraint.Update,
	MFUPT constraint.FieldsUpdatePtr[MFUT],
	MFUT constraint.FieldsUpdate,
	MDPT constraint.DeletePtr[MDT],
	MDT constraint.Delete,
	MDAT message.DeleteAddition,
] struct {
	resourceType string
	PubSubComponent
}

func (p *ResourcePubSubComponent[MAPT, MAT, MAAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT, MDAT]) PublishBatchAdded(md *message.Metadata, msg MAPT) {
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

func (p *ResourcePubSubComponent[MAPT, MAT, MAAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT, MDAT]) PublishUpdated(md *message.Metadata, msg MUPT) {
	log.Debugf("publish update %#v, %#v", md, msg)
	for topic, infos := range p.topicToSubscriberInfo {
		for _, info := range infos {
			if !info.GetSubscriptionSpec().Matches(md.GetDomainLcuuid()) {
				continue
			}

			if topic == TopicResourceUpdatedFields {
				info.GetSubscriber().(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg.GetFields().(MFUPT))
			}
			if topic == TopicResourceUpdatedFull {
				info.GetSubscriber().(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MAAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT, MDAT]) PublishBatchDeleted(md *message.Metadata, msg MDPT) {
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
