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

// Subscribe 提供订阅接口
// pubSubType: 消息中心类型
// topic: 主题
// subscriber: 订阅者
func Subscribe(pubSubType string, topic int, subscriber interface{}) error {
	return GetManager().Subscribe(pubSubType, topic, subscriber)
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
				// DomainPubSub
				PubSubTypeDomain: NewDomain(),

				// ResourcePubSub
				PubSubTypeAZ:                    NewAZ(),
				PubSubTypeRegion:                NewRegion(),
				PubSubTypeSubDomain:             NewSubDomain(),
				PubSubTypeHost:                  NewHost(),
				PubSubTypeVM:                    NewVM(),
				PubSubTypeVPC:                   NewVPC(),
				PubSubTypeNetwork:               NewNetwork(),
				PubSubTypeSubnet:                NewSubnet(),
				PubSubTypeVRouter:               NewVRouter(),
				PubSubTypeRoutingTable:          NewRoutingTable(),
				PubSubTypeDHCPPort:              NewDHCPPort(),
				PubSubTypeVInterface:            NewVInterface(),
				PubSubTypeFloatingIP:            NewFloatingIP(),
				PubSubTypeWANIP:                 NewWANIP(),
				PubSubTypeLANIP:                 NewLANIP(),
				PubSubTypeVIP:                   NewVIP(),
				PubSubTypeSecurityGroup:         NewSecurityGroup(),
				PubSubTypeSecurityGroupRule:     NewSecurityGroupRule(),
				PubSubTypeVMSecurityGroup:       NewVMSecurityGroup(),
				PubSubTypeNATGateway:            NewNATGateway(),
				PubSubTypeNATRule:               NewNATRule(),
				PubSubTypeNATVMConnection:       NewNATVMConnection(),
				PubSubTypeLB:                    NewLB(),
				PubSubTypeLBListener:            NewLBListener(),
				PubSubTypeLBTargetServer:        NewLBTargetServer(),
				PubSubTypeLBVMConnection:        NewLBVMConnection(),
				PubSubTypePeerConnection:        NewPeerConnection(),
				PubSubTypeCEN:                   NewCEN(),
				PubSubTypeRDSInstance:           NewRDSInstance(),
				PubSubTypeRedisInstance:         NewRedisInstance(),
				PubSubTypePodCluster:            NewPodCluster(),
				PubSubTypePodNode:               NewPodNode(),
				PubSubTypeVMPodNodeConnection:   NewVMPodNodeConnection(),
				PubSubTypePodNamespace:          NewPodNamespace(),
				PubSubTypePodIngress:            NewPodIngress(),
				PubSubTypePodIngressRule:        NewPodIngressRule(),
				PubSubTypePodIngressRuleBackend: NewPodIngressRuleBackend(),
				PubSubTypePodService:            NewPodService(),
				PubSubTypePodServicePort:        NewPodServicePort(),
				PubSubTypePodGroup:              NewPodGroup(),
				PubSubTypePodGroupPort:          NewPodGroupPort(),
				PubSubTypePodReplicaSet:         NewPodReplicaSet(),
				PubSubTypePod:                   NewPod(),
				PubSubTypeProcess:               NewProcess(),
				PubSubTypePrometheusTarget:      NewPrometheusTarget(),
			},
		}
	})
	return pubSubManager
}

type Manager struct {
	TypeToPubSub map[string]PubSub
}

func (m *Manager) Subscribe(pubSubType string, topic int, subscriber interface{}) error {
	ps, ok := m.TypeToPubSub[pubSubType]
	if !ok {
		log.Errorf("pubsub type not found: %d", pubSubType)
		return errors.New("pubsub type not found")
	}
	ps.Subscribe(topic, subscriber)
	return nil
}

func (m *Manager) GetPubSub(pubSubType string) PubSub {
	ps, ok := m.TypeToPubSub[pubSubType]
	if !ok {
		return nil
	}
	return ps
}
