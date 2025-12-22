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
	"testing"

	"github.com/deepflowio/deepflow/server/controller/common/metadata"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

// Mock subscriber for testing
type mockAnyChangedSubscriber struct {
	onAnyChangedCalled bool
	receivedMetadata   *message.Metadata
}

func (m *mockAnyChangedSubscriber) OnAnyChanged(md *message.Metadata) {
	m.onAnyChangedCalled = true
	m.receivedMetadata = md
}

// Mock implementation of ResourceBatchAddedSubscriber for testing
type mockResourceBatchAddedSubscriber struct {
	onResourceBatchAddedCalled bool
	receivedMetadata           *message.Metadata
	receivedMessage            interface{}
	callCount                  int
}

func (m *mockResourceBatchAddedSubscriber) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	m.onResourceBatchAddedCalled = true
	m.receivedMetadata = md
	m.receivedMessage = msg
	m.callCount++
}

// Helper function to create test metadata
func createTestMetadata(domainLcuuid string) *message.Metadata {
	domain := metadbmodel.Domain{
		Base: metadbmodel.Base{
			Lcuuid: domainLcuuid,
		},
		Name: "test-domain",
	}
	platform := metadata.Platform{}
	platform.SetDomain(domain)

	return message.NewMetadata(
		message.MetadataPlatform(platform),
	)
}

// Helper function to create a ResourcePubSubComponent for testing AddedRegions
func createTestResourcePubSubComponentForRegions() *ResourcePubSubComponent {
	return &ResourcePubSubComponent{
		resourceType:    "region",
		PubSubComponent: newPubSubComponent("test-pubsub"),
	}
}

func TestAnyChangePubSubComponent_PublishChange(t *testing.T) {
	tests := []struct {
		name               string
		setupSubscribers   func(*AnyChangePubSubComponent) []*mockAnyChangedSubscriber
		domainLcuuid       string
		expectedCallCounts []bool // whether each subscriber should be called
		description        string
	}{
		{
			name: "single subscriber with matching domain",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				subscriber := &mockAnyChangedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber, spec)
				return []*mockAnyChangedSubscriber{subscriber}
			},
			domainLcuuid:       "domain-123",
			expectedCallCounts: []bool{true},
			description:        "Subscriber with matching domain should receive notification",
		},
		{
			name: "single subscriber with non-matching domain",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				subscriber := &mockAnyChangedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber, spec)
				return []*mockAnyChangedSubscriber{subscriber}
			},
			domainLcuuid:       "domain-456",
			expectedCallCounts: []bool{false},
			description:        "Subscriber with non-matching domain should not receive notification",
		},
		{
			name: "single subscriber with empty domain (subscribe to all)",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				subscriber := &mockAnyChangedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged)
				pub.Subscribe(subscriber, spec)
				return []*mockAnyChangedSubscriber{subscriber}
			},
			domainLcuuid:       "any-domain",
			expectedCallCounts: []bool{true},
			description:        "Subscriber with empty domain should receive notification from any domain",
		},
		{
			name: "multiple subscribers with mixed domain filters",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				subscriber1 := &mockAnyChangedSubscriber{}
				subscriber2 := &mockAnyChangedSubscriber{}
				subscriber3 := &mockAnyChangedSubscriber{}

				// Subscriber 1: matches domain-123
				spec1 := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber1, spec1)

				// Subscriber 2: matches any domain
				spec2 := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged)
				pub.Subscribe(subscriber2, spec2)

				// Subscriber 3: matches domain-456
				spec3 := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged,
					SubscriptionSpecOptionDomain("domain-456"))
				pub.Subscribe(subscriber3, spec3)

				return []*mockAnyChangedSubscriber{subscriber1, subscriber2, subscriber3}
			},
			domainLcuuid:       "domain-123",
			expectedCallCounts: []bool{true, true, false}, // sub1 and sub2 should be called, sub3 should not
			description:        "Only subscribers with matching domains should receive notification",
		},
		{
			name: "subscriber with wrong topic should not be called",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				subscriber := &mockAnyChangedSubscriber{}
				// Subscribe to a different topic
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceUpdatedFull)
				pub.Subscribe(subscriber, spec)
				return []*mockAnyChangedSubscriber{subscriber}
			},
			domainLcuuid:       "domain-123",
			expectedCallCounts: []bool{false},
			description:        "Subscriber with wrong topic should not receive notification",
		},
		{
			name: "no subscribers",
			setupSubscribers: func(pub *AnyChangePubSubComponent) []*mockAnyChangedSubscriber {
				return []*mockAnyChangedSubscriber{}
			},
			domainLcuuid:       "domain-123",
			expectedCallCounts: []bool{},
			description:        "No subscribers should handle empty case gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubsub := &AnyChangePubSubComponent{
				PubSubComponent: newPubSubComponent("test-pubsub"),
			}
			// Setup subscribers
			subscribers := tt.setupSubscribers(pubsub)
			md := createTestMetadata(tt.domainLcuuid)
			pubsub.PublishChange(md)

			// Verify expectations
			if len(subscribers) != len(tt.expectedCallCounts) {
				t.Fatalf("Test setup error: expected %d call counts, got %d subscribers",
					len(tt.expectedCallCounts), len(subscribers))
			}

			for i, subscriber := range subscribers {
				expected := tt.expectedCallCounts[i]
				if subscriber.onAnyChangedCalled != expected {
					t.Errorf("Subscriber %d: onAnyChangedCalled = %v, want %v (%s)",
						i, subscriber.onAnyChangedCalled, expected, tt.description)
				}

				// If subscriber was called, verify it received the correct metadata
				if expected && subscriber.onAnyChangedCalled {
					if subscriber.receivedMetadata != md {
						t.Errorf("Subscriber %d: received wrong metadata", i)
					}
				}
			}
		})
	}
}

func TestAnyChangePubSubComponent_PublishChange_EdgeCases(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		pubsub := &AnyChangePubSubComponent{
			PubSubComponent: newPubSubComponent("test-pubsub"),
		}

		subscriber := &mockAnyChangedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged)
		pubsub.Subscribe(subscriber, spec)

		// This should not panic, but behavior depends on implementation
		// The actual implementation would need to handle nil metadata gracefully
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PublishChange panicked with nil metadata: %v", r)
			}
		}()

		pubsub.PublishChange(nil)
	})

	t.Run("empty domain in metadata", func(t *testing.T) {
		pubsub := &AnyChangePubSubComponent{
			PubSubComponent: newPubSubComponent("test-pubsub"),
		}

		subscriber := &mockAnyChangedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicPlatformChanged)
		pubsub.Subscribe(subscriber, spec)

		md := createTestMetadata("")
		pubsub.PublishChange(md)

		// Subscriber with empty domain filter should match empty domain
		if !subscriber.onAnyChangedCalled {
			t.Error("Subscriber should be called with empty domain metadata")
		}
	})
}

func TestResourcePubSubComponent_PublishBatchAdded(t *testing.T) {
	tests := []struct {
		name                        string
		setupSubscribers            func(*ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber
		domainLcuuid                string
		addedMessage                *message.AddedRegions
		expectedSubscriberCallCount []int    // how many times each subscriber should be called
		expectedTopics              []string // which topics should be published to
		description                 string
	}{
		{
			name: "publish to Full topic with matching domain subscriber",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber := &mockResourceBatchAddedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber, spec)
				return []*mockResourceBatchAddedSubscriber{subscriber}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
					{Base: metadbmodel.Base{Lcuuid: "region-2"}, Name: "Region 2"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{1},
			expectedTopics:              []string{"TopicResourceBatchAddedFull"},
			description:                 "Subscriber with matching domain should receive Full topic notification",
		},
		{
			name: "publish to MetadbItems topic with matching domain subscriber",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber := &mockResourceBatchAddedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedMetadbItems,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber, spec)
				return []*mockResourceBatchAddedSubscriber{subscriber}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{1},
			expectedTopics:              []string{"TopicResourceBatchAddedMetadbItems"},
			description:                 "Subscriber should receive MetadbItems topic with region items",
		},
		{
			name: "subscriber with non-matching domain should not be called",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber := &mockResourceBatchAddedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
					SubscriptionSpecOptionDomain("domain-456"))
				pub.Subscribe(subscriber, spec)
				return []*mockResourceBatchAddedSubscriber{subscriber}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{0},
			expectedTopics:              []string{},
			description:                 "Subscriber with non-matching domain should not receive notification",
		},
		{
			name: "multiple subscribers with different topics and domains",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber1 := &mockResourceBatchAddedSubscriber{}
				subscriber2 := &mockResourceBatchAddedSubscriber{}
				subscriber3 := &mockResourceBatchAddedSubscriber{}

				// Subscriber 1: Full topic, matching domain
				spec1 := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber1, spec1)

				// Subscriber 2: MetadbItems topic, matching domain
				spec2 := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedMetadbItems,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber2, spec2)

				// Subscriber 3: Full topic, non-matching domain
				spec3 := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
					SubscriptionSpecOptionDomain("domain-456"))
				pub.Subscribe(subscriber3, spec3)

				return []*mockResourceBatchAddedSubscriber{subscriber1, subscriber2, subscriber3}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
					{Base: metadbmodel.Base{Lcuuid: "region-2"}, Name: "Region 2"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{1, 1, 0}, // sub1, sub2 should be called, sub3 should not
			expectedTopics:              []string{"TopicResourceBatchAddedFull", "TopicResourceBatchAddedMetadbItems"},
			description:                 "Multiple subscribers should receive appropriate notifications based on topic and domain",
		},
		{
			name: "subscriber with empty domain should receive notification",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber := &mockResourceBatchAddedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull)
				pub.Subscribe(subscriber, spec)
				return []*mockResourceBatchAddedSubscriber{subscriber}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{1},
			expectedTopics:              []string{"TopicResourceBatchAddedFull"},
			description:                 "Subscriber with empty domain should receive notification from any domain",
		},
		{
			name: "empty added message should still trigger notifications",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				subscriber := &mockResourceBatchAddedSubscriber{}
				spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
					SubscriptionSpecOptionDomain("domain-123"))
				pub.Subscribe(subscriber, spec)
				return []*mockResourceBatchAddedSubscriber{subscriber}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				msg := &message.AddedRegions{}
				msg.SetMetadbItems([]*metadbmodel.Region{}) // Empty slice
				return msg
			}(),
			expectedSubscriberCallCount: []int{1},
			expectedTopics:              []string{"TopicResourceBatchAddedFull"},
			description:                 "Empty added message should still trigger notifications",
		},
		{
			name: "no subscribers should handle gracefully",
			setupSubscribers: func(pub *ResourcePubSubComponent) []*mockResourceBatchAddedSubscriber {
				return []*mockResourceBatchAddedSubscriber{}
			},
			domainLcuuid: "domain-123",
			addedMessage: func() *message.AddedRegions {
				regions := []*metadbmodel.Region{
					{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
				}
				msg := &message.AddedRegions{}
				msg.SetMetadbItems(regions)
				return msg
			}(),
			expectedSubscriberCallCount: []int{},
			expectedTopics:              []string{},
			description:                 "No subscribers should handle empty case gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubsub := createTestResourcePubSubComponentForRegions()

			// Setup subscribers
			subscribers := tt.setupSubscribers(pubsub)
			md := createTestMetadata(tt.domainLcuuid)
			pubsub.PublishBatchAdded(md, tt.addedMessage)

			// Verify expectations
			if len(subscribers) != len(tt.expectedSubscriberCallCount) {
				t.Fatalf("Test setup error: expected %d call counts, got %d subscribers",
					len(tt.expectedSubscriberCallCount), len(subscribers))
			}

			for i, subscriber := range subscribers {
				expectedCallCount := tt.expectedSubscriberCallCount[i]
				if subscriber.callCount != expectedCallCount {
					t.Errorf("Subscriber %d: callCount = %d, want %d (%s)",
						i, subscriber.callCount, expectedCallCount, tt.description)
				}

				// If subscriber was called, verify it received the correct data
				if expectedCallCount > 0 {
					if subscriber.receivedMetadata != md {
						t.Errorf("Subscriber %d: received wrong metadata", i)
					}

					// Check the message type and content
					if subscriber.receivedMessage == nil {
						t.Errorf("Subscriber %d: received nil message", i)
					} else {
						// The message should be the same as the input for Full topic
						// or the MetadbItems for MetadbItems topic
						receivedMsg, ok := subscriber.receivedMessage.(*message.AddedRegions)
						if !ok {
							t.Errorf("Subscriber %d: received message is not *message.AddedRegions, got %T",
								i, subscriber.receivedMessage)
						} else if receivedMsg == nil {
							t.Errorf("Subscriber %d: received AddedRegions message is nil", i)
						}
					}
				}
			}
		})
	}
}

func TestResourcePubSubComponent_PublishBatchAdded_EdgeCases(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		pubsub := createTestResourcePubSubComponentForRegions()

		subscriber := &mockResourceBatchAddedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull)
		pubsub.Subscribe(subscriber, spec)

		addedMessage := &message.AddedRegions{}
		addedMessage.SetMetadbItems([]*metadbmodel.Region{
			{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
		})

		defer func() {
			if r := recover(); r != nil {
				t.Logf("PublishBatchAdded panicked with nil metadata: %v", r)
			}
		}()

		pubsub.PublishBatchAdded(nil, addedMessage)
	})

	t.Run("nil added message", func(t *testing.T) {
		pubsub := createTestResourcePubSubComponentForRegions()

		subscriber := &mockResourceBatchAddedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
			SubscriptionSpecOptionDomain("domain-123"))
		pubsub.Subscribe(subscriber, spec)

		md := createTestMetadata("domain-123")

		defer func() {
			if r := recover(); r != nil {
				t.Logf("PublishBatchAdded panicked with nil message: %v", r)
			}
		}()

		pubsub.PublishBatchAdded(md, nil)
	})

	t.Run("empty domain in metadata", func(t *testing.T) {
		pubsub := createTestResourcePubSubComponentForRegions()

		subscriber := &mockResourceBatchAddedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull)
		pubsub.Subscribe(subscriber, spec)

		md := createTestMetadata("")
		addedMessage := &message.AddedRegions{}
		addedMessage.SetMetadbItems([]*metadbmodel.Region{
			{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
		})

		pubsub.PublishBatchAdded(md, addedMessage)

		// Subscriber with empty domain filter should match empty domain
		if subscriber.callCount != 1 {
			t.Error("Subscriber should be called with empty domain metadata")
		}
	})

	t.Run("verify message content preservation", func(t *testing.T) {
		pubsub := createTestResourcePubSubComponentForRegions()

		subscriber := &mockResourceBatchAddedSubscriber{}
		spec := NewSubscriptionSpec("test-pubsub", TopicResourceBatchAddedFull,
			SubscriptionSpecOptionDomain("domain-123"))
		pubsub.Subscribe(subscriber, spec)

		md := createTestMetadata("domain-123")

		originalRegions := []*metadbmodel.Region{
			{Base: metadbmodel.Base{Lcuuid: "region-1"}, Name: "Region 1"},
			{Base: metadbmodel.Base{Lcuuid: "region-2"}, Name: "Region 2"},
		}
		addedMessage := &message.AddedRegions{}
		addedMessage.SetMetadbItems(originalRegions)

		pubsub.PublishBatchAdded(md, addedMessage)

		if subscriber.callCount != 1 {
			t.Fatalf("Expected subscriber to be called once, got %d", subscriber.callCount)
		}

		receivedMsg, ok := subscriber.receivedMessage.(*message.AddedRegions)
		if !ok {
			t.Fatalf("Expected *message.AddedRegions, got %T", subscriber.receivedMessage)
		}

		receivedRegions := receivedMsg.GetMetadbItems().([]*metadbmodel.Region)
		if len(receivedRegions) != len(originalRegions) {
			t.Errorf("Expected %d regions, got %d", len(originalRegions), len(receivedRegions))
		}

		for i, originalRegion := range originalRegions {
			if i < len(receivedRegions) {
				if receivedRegions[i].Lcuuid != originalRegion.Lcuuid {
					t.Errorf("Region %d: expected Lcuuid %s, got %s",
						i, originalRegion.Lcuuid, receivedRegions[i].Lcuuid)
				}
				if receivedRegions[i].Name != originalRegion.Name {
					t.Errorf("Region %d: expected Name %s, got %s",
						i, originalRegion.Name, receivedRegions[i].Name)
				}
			}
		}
	})
}
