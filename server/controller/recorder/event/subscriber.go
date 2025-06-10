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

package event

import (
	"sync"

	"github.com/deepflowio/deepflow/server/controller/recorder/event/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var (
	subscriberManagerOnce sync.Once
	subscriberManager     *SubscriberManager
)

type SubscriberManager struct {
	cfg         config.Config
	subscribers []Subscriber
}

func GetSubscriberManager() *SubscriberManager {
	subscriberManagerOnce.Do(func() {
		subscriberManager = &SubscriberManager{}
	})
	return subscriberManager
}

func (c *SubscriberManager) Start(cfg config.Config, q *queue.OverwriteQueue) (err error) {
	log.Info("resource event subscriber manager started")
	c.cfg = cfg
	c.subscribers = c.getSubscribers(q)
	for _, subscriber := range c.subscribers {
		subscriber.Subscribe()
	}
	return nil
}

func (c *SubscriberManager) getSubscribers(q *queue.OverwriteQueue) []Subscriber {
	subscribers := []Subscriber{
		NewWholeDomain(q),
		NewWholeSubDomain(q),

		NewHost(q),
		NewVM(q),
		NewDHCPPort(q),
		NewVRouter(q),
		NewWANIP(q),
		NewLANIP(q),
		NewLB(q),
		NewNATGateway(q),
		NewRDSInstance(q),
		NewRedisInstance(q),
		NewPodNode(q),
		NewPodService(c.cfg, q),
		NewPodGroup(c.cfg, q),
		NewPod(q),
		NewConfigMap(c.cfg, q),
		NewPodGroupConfigMapConnection(q),
		NewProcess(q),
	}
	return subscribers
}

type Subscriber interface {
	pubsub.Subscriber
}

type SubscriberComponent struct {
	subResourceTypeName string // 订阅表资源类型，即源表资源类型
	subTopics           []int
	subscriberSelf      interface{}
}

func newSubscriberComponent(
	sourceResourceTypeName string, topicOptions ...TopicOption,
) SubscriberComponent {
	s := SubscriberComponent{
		subResourceTypeName: sourceResourceTypeName,
	}
	for _, option := range topicOptions {
		option(&s)
	}
	return s
}

func (s *SubscriberComponent) SetSubscriberSelf(subscriber interface{}) {
	s.subscriberSelf = subscriber
}

func (s *SubscriberComponent) GetSubResourceType() string {
	return s.subResourceTypeName
}

func (s *SubscriberComponent) Subscribe() {
	for _, topic := range s.subTopics {
		log.Info("subscribe topic: ", topic, " from resource type: ", s.subResourceTypeName)
		pubsub.Subscribe(s.subResourceTypeName, topic, s.subscriberSelf)
	}
}

type ChangedSubscriberComponent struct {
	SubscriberComponent
}

func newChangedSubscriberComponent(
	sourceResourceTypeName string, topicOptions ...TopicOption,
) ChangedSubscriberComponent {
	s := ChangedSubscriberComponent{
		newSubscriberComponent(sourceResourceTypeName, topicOptions...),
	}
	s.subTopics = append(
		s.subTopics,
		pubsub.TopicPlatformResourceChanged,
	)
	return s
}

type CUDSubscriberComponent struct {
	SubscriberComponent
}

func newCUDSubscriberComponent(
	sourceResourceTypeName string, topicOptions ...TopicOption,
) CUDSubscriberComponent {
	s := CUDSubscriberComponent{
		newSubscriberComponent(sourceResourceTypeName, topicOptions...),
	}
	s.subTopics = append(
		s.subTopics,
		pubsub.TopicResourceBatchAddedMySQL,
		pubsub.TopicResourceBatchDeletedMySQL,
	)
	return s
}

// TODO remove
func (s *CUDSubscriberComponent) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
}

type TopicOption func(*SubscriberComponent)

func SubTopic(topic int) func(*SubscriberComponent) {
	return func(s *SubscriberComponent) {
		s.subTopics = append(s.subTopics, topic)
	}
}
