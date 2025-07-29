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
	Subscribe(topic int, subscriber interface{})
	Unsubscribe(topic int, subscriber interface{})
}

type PubSubComponent struct {
	pubSubType  string
	subscribers map[int][]interface{} // key: topic, value: subscribers
}

func newPubSubComponent(pubsubType string) PubSubComponent {
	return PubSubComponent{
		pubSubType:  pubsubType,
		subscribers: make(map[int][]interface{}),
	}
}

func (p *PubSubComponent) Subscribe(topic int, subscriber interface{}) {
	// log.Infof("subscribe topic: %d to pubsub: %s from subscriber: %#v", topic, p.pubSubType, subscriber)
	if _, exists := p.subscribers[topic]; !exists {
		p.subscribers[topic] = []interface{}{}
	}
	p.subscribers[topic] = append(p.subscribers[topic], subscriber)
}

func (p *PubSubComponent) Unsubscribe(topic int, subscriber interface{}) {
	if _, exists := p.subscribers[topic]; !exists {
		return
	}
	for i, sub := range p.subscribers[topic] {
		if sub == subscriber {
			p.subscribers[topic] = append(p.subscribers[topic][:i], p.subscribers[topic][i+1:]...)
			return
		}
	}
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
	for topic, subs := range p.subscribers {
		if topic == TopicPlatformResourceChanged {
			for _, sub := range subs {
				sub.(AnyChangedSubscriber).OnAnyChanged(md)
			}
		}
	}
}

const (
	TopicPlatformResourceChanged     = iota // subscribe to this topic to get notification of resource changed
	TopicResourceBatchAddedMessage          // subscribe to this topic to get message add model data of resource batch added
	TopicResourceBatchAddedMetadb           // subscribe to this topic to get Metadb model data of resource batch added
	TopicResourceUpdatedFields              // subscribe to this topic to get message update model data of resource updated
	TopicResourceUpdatedMessage             // subscribe to this topic to get message update model data of resource updated
	TopicResourceBatchDeletedLcuuid         // subscribe to this topic to get lcuuids of resource batch deleted
	TopicResourceBatchDeletedMetadb         // subscribe to this topic to get Metadb model data of resource batch deleted
	TopicResourceBatchDeletedMessage        // subscribe to this topic to get message delete model data of resource batch deleted
)

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
	for topic, subs := range p.subscribers {
		if topic == TopicResourceBatchAddedMetadb {
			for _, sub := range subs {
				sub.(ResourceBatchAddedSubscriber).OnResourceBatchAdded(md, msg.GetMetadbItems())
			}
		}
		if topic == TopicResourceBatchAddedMessage {
			for _, sub := range subs {
				sub.(ResourceBatchAddedSubscriber).OnResourceBatchAdded(md, msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MAAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT, MDAT]) PublishUpdated(md *message.Metadata, msg MUPT) {
	log.Debugf("publish update %#v, %#v", md, msg)
	for topic, subs := range p.subscribers {
		if topic == TopicResourceUpdatedFields {
			for _, sub := range subs {
				sub.(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg.GetFields().(MFUPT))
			}
		}
		if topic == TopicResourceUpdatedMessage {
			for _, sub := range subs {
				sub.(ResourceUpdatedSubscriber).OnResourceUpdated(md, msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MAAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT, MDAT]) PublishBatchDeleted(md *message.Metadata, msg MDPT) {
	log.Debugf("publish delete %#v, %#v", md, msg)
	for topic, subs := range p.subscribers {
		if topic == TopicResourceBatchDeletedLcuuid {
			for _, sub := range subs {
				sub.(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg.GetLcuuids())
			}
		}
		if topic == TopicResourceBatchDeletedMetadb {
			for _, sub := range subs {
				sub.(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg.GetMetadbItems())
			}
		}
		if topic == TopicResourceBatchDeletedMessage {
			for _, sub := range subs {
				sub.(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(md, msg)
			}
		}
	}
}
