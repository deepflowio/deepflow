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

import "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"

// newSubscriberInfo creates a new subscriber info
func newSubscriberInfo(subscriber interface{}, spec *SubscriptionSpec) *SubscriberInfo {
	return &SubscriberInfo{
		subscriber: subscriber,
		spec:       spec,
	}
}

// SubscriberInfo encapsulates subscriber instance and its subscription specification
type SubscriberInfo struct {
	// subscriber is the subscriber instance
	subscriber interface{}
	// spec defines the subscription conditions and filtering rules
	spec *SubscriptionSpec
}

func (si SubscriberInfo) GetSubscriber() interface{} {
	return si.subscriber
}

func (si SubscriberInfo) GetSubscriptionSpec() *SubscriptionSpec {
	return si.spec
}

type Subscriber interface {
	Subscribe()
}

type AnyChangedSubscriber interface {
	OnAnyChanged(md *message.Metadata)
}

type ResourceBatchAddedSubscriber interface {
	OnResourceBatchAdded(md *message.Metadata, msg interface{})
}

type ResourceUpdatedSubscriber interface {
	OnResourceUpdated(md *message.Metadata, msg interface{})
}

type ResourceBatchDeletedSubscriber interface {
	OnResourceBatchDeleted(md *message.Metadata, msg interface{})
}
