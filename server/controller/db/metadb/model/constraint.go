/*
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

package model

import (
	"time"
)

// AssetResourceConstraintPtr is a pointer of AssetResourceConstraint.
type AssetResourceConstraintPtr[T AssetResourceConstraint] interface {
	*T

	GetLcuuid() string
	GetID() int

	SetID(int)
	SetUpdatedAt(time.Time)
	GetUpdatedAt() time.Time
}

// AssetResourceConstraint is a constraint of asset resource db models.
type AssetResourceConstraint interface {
	Region | AZ | SubDomain | Host | VM |
		VPC | Network | Subnet | VRouter | RoutingTable |
		DHCPPort | VInterface | WANIP | LANIP | FloatingIP |
		NATGateway | NATRule | NATVMConnection | LB |
		LBListener | LBTargetServer | LBVMConnection | CEN |
		PeerConnection | RDSInstance | RedisInstance | PodCluster |
		PodNode | VMPodNodeConnection | PodNamespace | PodIngress |
		PodIngressRule | PodIngressRuleBackend | PodService |
		PodServicePort | PodGroup | ConfigMap | PodGroupConfigMapConnection |
		PodGroupPort | PodReplicaSet | Pod | Process | VIP | CustomService

	GetID() int
	GetUpdatedAt() time.Time
}

// ResourceNeedBeAllocatedIDConstraint is a constraint of resource db modelsthat needs to be allocated ID manully.
type ResourceNeedBeAllocatedIDConstraint interface {
	Region | AZ | SubDomain | Host | VM |
		VPC | Network | VRouter | DHCPPort |
		NATGateway | LB | CEN |
		PeerConnection | RDSInstance | RedisInstance | PodCluster |
		PodNode | VMPodNodeConnection | PodNamespace | PodIngress |
		PodService | PodGroup | PodReplicaSet |
		Pod | Process | VTap | ORG

	GetID() int
}
