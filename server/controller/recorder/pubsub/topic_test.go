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
)

func TestNewSubscriptionSpec(t *testing.T) {
	tests := []struct {
		name       string
		pubSubType string
		topic      int
		options    []SubscriptionSpecOption
		expected   *SubscriptionSpec
	}{
		{
			name:       "basic subscription spec without domain",
			pubSubType: "vm",
			topic:      TopicResourceUpdatedFull,
			options:    nil,
			expected: &SubscriptionSpec{
				PubSubType:          "vm",
				Topic:               TopicResourceUpdatedFull,
				PublisherDomainUUID: "",
			},
		},
		{
			name:       "subscription spec with domain",
			pubSubType: "host",
			topic:      TopicPlatformChanged,
			options:    []SubscriptionSpecOption{SubscriptionSpecOptionDomain("domain-123")},
			expected: &SubscriptionSpec{
				PubSubType:          "host",
				Topic:               TopicPlatformChanged,
				PublisherDomainUUID: "domain-123",
			},
		},
		{
			name:       "subscription spec with multiple options",
			pubSubType: "pod",
			topic:      TopicResourceBatchAddedFull,
			options: []SubscriptionSpecOption{
				SubscriptionSpecOptionDomain("domain-456"),
			},
			expected: &SubscriptionSpec{
				PubSubType:          "pod",
				Topic:               TopicResourceBatchAddedFull,
				PublisherDomainUUID: "domain-456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := NewSubscriptionSpec(tt.pubSubType, tt.topic, tt.options...)

			if spec.PubSubType != tt.expected.PubSubType {
				t.Errorf("PubSubType = %v, want %v", spec.PubSubType, tt.expected.PubSubType)
			}
			if spec.Topic != tt.expected.Topic {
				t.Errorf("Topic = %v, want %v", spec.Topic, tt.expected.Topic)
			}
			if spec.PublisherDomainUUID != tt.expected.PublisherDomainUUID {
				t.Errorf("PublisherDomainUUID = %v, want %v", spec.PublisherDomainUUID, tt.expected.PublisherDomainUUID)
			}
		})
	}
}

func TestSubscriptionSpecMatches(t *testing.T) {
	tests := []struct {
		name       string
		spec       *SubscriptionSpec
		domainUUID string
		expected   bool
	}{
		{
			name: "matches with empty domain (subscribe to all)",
			spec: &SubscriptionSpec{
				PubSubType:          "vm",
				Topic:               TopicResourceUpdatedFull,
				PublisherDomainUUID: "",
			},
			domainUUID: "any-domain",
			expected:   true,
		},
		{
			name: "matches with specific domain",
			spec: &SubscriptionSpec{
				PubSubType:          "host",
				Topic:               TopicPlatformChanged,
				PublisherDomainUUID: "domain-123",
			},
			domainUUID: "domain-123",
			expected:   true,
		},
		{
			name: "does not match with different domain",
			spec: &SubscriptionSpec{
				PubSubType:          "pod",
				Topic:               TopicResourceBatchAddedFull,
				PublisherDomainUUID: "domain-123",
			},
			domainUUID: "domain-456",
			expected:   false,
		},
		{
			name: "matches with empty string domain and empty spec domain",
			spec: &SubscriptionSpec{
				PubSubType:          "network",
				Topic:               TopicResourceBatchDeletedFull,
				PublisherDomainUUID: "",
			},
			domainUUID: "",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.spec.Matches(tt.domainUUID)
			if result != tt.expected {
				t.Errorf("Matches(%v) = %v, want %v", tt.domainUUID, result, tt.expected)
			}
		})
	}
}

func TestSubscriptionSpecOptionDomain(t *testing.T) {
	spec := &SubscriptionSpec{}
	option := SubscriptionSpecOptionDomain("test-domain")
	option(spec)

	if spec.PublisherDomainUUID != "test-domain" {
		t.Errorf("PublisherDomainUUID = %v, want test-domain", spec.PublisherDomainUUID)
	}
}

func TestSubscriptionSpecWithAllTopics(t *testing.T) {
	// Test with all defined topic constants
	topics := []int{
		TopicPlatformChanged,
		TopicResourceBatchAddedFull,
		TopicResourceBatchAddedMetadbItems,
		TopicResourceUpdatedFields,
		TopicResourceUpdatedFull,
		TopicResourceBatchDeletedLcuuids,
		TopicResourceBatchDeletedMetadbItems,
		TopicResourceBatchDeletedFull,
	}

	for _, topic := range topics {
		t.Run("topic_"+string(rune(topic)), func(t *testing.T) {
			spec := NewSubscriptionSpec("test-pubsub", topic)
			if spec.Topic != topic {
				t.Errorf("Topic = %v, want %v", spec.Topic, topic)
			}
			if spec.PubSubType != "test-pubsub" {
				t.Errorf("PubSubType = %v, want test-pubsub", spec.PubSubType)
			}
		})
	}
}

func TestSubscriptionSpecEdgeCases(t *testing.T) {
	t.Run("empty pubsub type", func(t *testing.T) {
		spec := NewSubscriptionSpec("", TopicPlatformChanged)
		if spec.PubSubType != "" {
			t.Errorf("PubSubType should be empty string")
		}
	})

	t.Run("negative topic value", func(t *testing.T) {
		spec := NewSubscriptionSpec("test", -1)
		if spec.Topic != -1 {
			t.Errorf("Topic = %v, want -1", spec.Topic)
		}
	})

	t.Run("multiple domain options (last one wins)", func(t *testing.T) {
		spec := NewSubscriptionSpec("test", TopicPlatformChanged,
			SubscriptionSpecOptionDomain("domain-1"),
			SubscriptionSpecOptionDomain("domain-2"),
		)
		if spec.PublisherDomainUUID != "domain-2" {
			t.Errorf("PublisherDomainUUID = %v, want domain-2", spec.PublisherDomainUUID)
		}
	})
}
