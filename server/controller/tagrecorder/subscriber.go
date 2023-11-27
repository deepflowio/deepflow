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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	msgconstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder/config"
)

type Subscriber interface {
	Subscribe()
	SetConfig(config.TagRecorderConfig)
}

type SubscriberDataGenerator[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey] interface {
	sourceToTarget(resourceMySQLItem *MT) (keys []KT, chItems []CT)
	onResourceUpdated(int, MUPT)
}

type SubscriberComponent[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey] struct {
	cfg config.TagRecorderConfig

	resourceTypeName string
	dbOperator       operator[CT, KT]
	subscriberDG     SubscriberDataGenerator[MUPT, MUT, MT, CT, KT]
}

func newSubscriberComponent[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey](
	resourceType string,
) SubscriberComponent[MUPT, MUT, MT, CT, KT] {
	s := SubscriberComponent[MUPT, MUT, MT, CT, KT]{
		resourceTypeName: resourceType,
	}
	s.initDBOperator()
	return s
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) initDBOperator() {
	s.dbOperator = newOperator[CT, KT](s.resourceTypeName)
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) generateKeyTargets(sources []*MT) ([]KT, []CT) {
	keys := []KT{}
	targets := []CT{}
	for _, item := range sources {
		ks, ts := s.subscriberDG.sourceToTarget(item)
		keys = append(keys, ks...)
		targets = append(targets, ts...)
	}
	return keys, targets
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) SetConfig(cfg config.TagRecorderConfig) {
	s.cfg = cfg
	s.dbOperator.setConfig(cfg)
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) Subscribe() {
	pubSubType, ok := pubsub.ResourceTypeToPubsubType[s.resourceTypeName]
	if !ok {
		log.Errorf("resource type %s not found in pubsub type map", s.resourceTypeName)
		return
	}
	pubsub.Subscribe(pubSubType, pubsub.TopicResourceBatchAddedMySQL, s)
	pubsub.Subscribe(pubSubType, pubsub.TopicResourceUpdatedFields, s)
	pubsub.Subscribe(pubSubType, pubsub.TopicResourceBatchDeletedMySQL, s)
}

// OnResourceBatchAdded implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceBatchAdded(msg interface{}) {
	items := msg.([]*MT)
	keys, chItems := s.generateKeyTargets(items)
	// TODO refresh control
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.add)
}

// OnResourceBatchUpdated implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceUpdated(msg interface{}) {
	log.Infof("OnResourceUpdated resource type %s: %v", s.resourceTypeName, msg)
	updateFields := msg.(MUPT)
	s.subscriberDG.onResourceUpdated(updateFields.GetID(), updateFields)
}

// OnResourceBatchDeleted implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceBatchDeleted(msg interface{}) {
	items := msg.([]*MT)
	keys, chItems := s.generateKeyTargets(items)
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.delete)
}
