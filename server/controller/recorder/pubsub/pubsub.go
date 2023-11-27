/**
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
)

var log = logging.MustGetLogger("recorder.pubsub")

type PubSub interface {
	Subscribe(topic int, subscriber interface{})   // 用于订阅某个主题的消息
	Unsubscribe(topic int, subscriber interface{}) // 用于取消订阅某个主题的消息
}

type PubSubComponent struct {
	pubSubType  int
	subscribers map[int][]interface{} // key: topic, value: subscribers
}

func newPubSubComponent(pubsubType int) PubSubComponent {
	return PubSubComponent{
		pubSubType:  pubsubType,
		subscribers: make(map[int][]interface{}),
	}
}

func (p *PubSubComponent) Subscribe(topic int, subscriber interface{}) {
	log.Infof("subscribe topic %d, to %d, from %#v", topic, p.pubSubType, subscriber)
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

// 整体云平台的 PubSub 接口
type DomainPubSub interface {
	PubSub
	PublishChange() // 发布云平台任意变更的通知，仅通知已变更这一事实，不包含具体的变更数据
}

const (
	TopicResourceChanged              = iota // subscribe to this topic to get notification of resource changed
	TopicResourceBatchAddedMySQL             // subscribe to this topic to get MySQL model data of resource batch added
	TopicResourceUpdatedFields               // subscribe to this topic to get message update model data of resource updated
	TopicResourceUpdatedMessageUpdate        // subscribe to this topic to get message update model data of resource updated
	TopicResourceBatchDeletedLcuuid          // subscribe to this topic to get lcuuids of resource batch deleted
	TopicResourceBatchDeletedMySQL           // subscribe to this topic to get MySQL model data of resource batch deleted
)

// 某一资源的 PubSub 接口
type ResourcePubSub[
	MAPT constraint.AddPtr[MAT],
	MAT constraint.Add,
	MUPT constraint.UpdatePtr[MUT],
	MUT constraint.Update,
	MFUPT constraint.FieldsUpdatePtr[MFUT],
	MFUT constraint.FieldsUpdate,
	MDPT constraint.DeletePtr[MDT],
	MDT constraint.Delete,
] interface {
	PubSub
	PublishChange()           // 发布资源任意变更的通知，仅通知资源已变更这一事实，不包含具体的变更数据
	PublishBatchAdded(MAPT)   // 发布资源新增的通知，包含具体数据
	PublishUpdated(MUPT)      // 发布资源更新的通知，包含具体数据
	PublishBatchDeleted(MDPT) // 发布资源删除的通知，包含具体数据
}

type ResourcePubSubComponent[
	MAPT constraint.AddPtr[MAT],
	MAT constraint.Add,
	MUPT constraint.UpdatePtr[MUT],
	MUT constraint.Update,
	MFUPT constraint.FieldsUpdatePtr[MFUT],
	MFUT constraint.FieldsUpdate,
	MDPT constraint.DeletePtr[MDT],
	MDT constraint.Delete,
] struct {
	resourceType string
	PubSubComponent
}

func (p *ResourcePubSubComponent[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) PublishChange() {
	for topic, subs := range p.subscribers {
		if topic == TopicResourceChanged {
			for _, sub := range subs {
				sub.(ResourceChangedSubscriber).OnResourceChanged(nil)
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) PublishAdd(msg MAPT) {
	log.Infof("publish add %#v", msg)
	for topic, subs := range p.subscribers {
		if topic == TopicResourceBatchAddedMySQL {
			for _, sub := range subs {
				sub.(ResourceBatchAddedSubscriber).OnResourceBatchAdded(msg.GetMySQLItems())
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) PublishUpdate(msg MUPT) {
	log.Infof("publish update %#v", msg)
	for topic, subs := range p.subscribers {
		if topic == TopicResourceUpdatedFields {
			for _, sub := range subs {
				log.Infof("publish update %#v", msg.GetFields())
				sub.(ResourceUpdatedSubscriber).OnResourceUpdated(msg.GetFields().(MFUPT))
			}
		}
		if topic == TopicResourceUpdatedMessageUpdate {
			for _, sub := range subs {
				sub.(ResourceUpdatedSubscriber).OnResourceUpdated(msg)
			}
		}
	}
}

func (p *ResourcePubSubComponent[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) PublishDelete(msg MDPT) {
	log.Infof("publish delete %#v", msg)
	for topic, subs := range p.subscribers {
		if topic == TopicResourceBatchDeletedLcuuid {
			for _, sub := range subs {
				sub.(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(msg.GetLcuuids())
			}
		}
		if topic == TopicResourceBatchDeletedMySQL {
			for _, sub := range subs {
				sub.(ResourceBatchDeletedSubscriber).OnResourceBatchDeleted(msg.GetMySQLItems())
			}
		}
	}
}
