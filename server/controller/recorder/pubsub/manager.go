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
	"errors"
	"sync"
)

// Subscribe allows subscribers to subscribe to messages.
// Upon successful subscription, messages will be pushed to the subscriber according to the subscription speciification.
func Subscribe(subscriber interface{}, spec ...*SubscriptionSpec) error {
	mng := GetManager()
	for _, s := range spec {
		if err := mng.Subscribe(subscriber, s); err != nil {
			return err
		}
	}
	return nil
}

func GetPubSub(pubSubType string) interface{} {
	return GetManager().GetPubSub(pubSubType)
}

var (
	pubSubManagerOnce sync.Once
	pubSubManager     *Manager
)

func GetManager() *Manager {
	pubSubManagerOnce.Do(func() {
		pubSubManager = &Manager{
			TypeToPubSub: map[string]PubSub{
				PubSubTypeWholeDomain:    newAnyChangePubSub(PubSubTypeWholeDomain),
				PubSubTypeWholeSubDomain: newAnyChangePubSub(PubSubTypeWholeSubDomain),
			},
		}
		for pubSubType := range rscPubSubTypeToResourceType {
			pubSubManager.TypeToPubSub[pubSubType] = newResourcePubSub(pubSubType)
		}
	})
	return pubSubManager
}

type Manager struct {
	TypeToPubSub map[string]PubSub
}

func (m *Manager) Subscribe(subscriber interface{}, spec *SubscriptionSpec) error {
	ps, ok := m.TypeToPubSub[spec.PubSubType]
	if !ok {
		log.Errorf("pubsub type not found: %s", spec.PubSubType)
		return errors.New("pubsub type not found")
	}
	ps.Subscribe(subscriber, spec)
	return nil
}

func (m *Manager) GetPubSub(pubSubType string) PubSub {
	ps, ok := m.TypeToPubSub[pubSubType]
	if !ok {
		return nil
	}
	return ps
}
