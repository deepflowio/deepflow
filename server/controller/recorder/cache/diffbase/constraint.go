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

package diffbase

import (
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type CollectionConstriant interface {
	*RegionCollection | *AZCollection | *SubDomainCollection | *HostCollection | *VMCollection |
		*VPCCollection | *NetworkCollection | *SubnetCollection | *VRouterCollection | *RoutingTableCollection |
		*DHCPPortCollection | *VInterfaceCollection | *WANIPCollection | *LANIPCollection | *FloatingIPCollection |
		*NATGatewayCollection | *NATRuleCollection | *NATVMConnectionCollection | *LBCollection |
		*LBListenerCollection | *LBTargetServerCollection | *LBVMConnectionCollection | *CENCollection |
		*PeerConnectionCollection | *RDSInstanceCollection | *RedisInstanceCollection | *PodClusterCollection |
		*PodNodeCollection | *VMPodNodeConnectionCollection | *PodNamespaceCollection | *PodIngressCollection |
		*PodIngressRuleCollection | *PodIngressRuleBackendCollection | *PodServiceCollection |
		*PodServicePortCollection | *PodGroupCollection | *ConfigMapCollection | *PodGroupConfigMapConnectionCollection |
		*PodGroupPortCollection | *PodReplicaSetCollection | *PodCollection | *ProcessCollection | *VIPCollection

	GetResourceType() string

	Add(seq int, dbData interface{})
	Update(dbData interface{})
	Delete(lcuuid string)
}

type DiffBaseConstraintPointer[
	DT DiffBaseConstraint,
	MPT metadbmodel.AssetResourceConstraintPtr[MT],
	MT metadbmodel.AssetResourceConstraint,
] interface {
	*DT

	GetSequence() int
	ResetSequence(seq int)
	GetLcuuid() string

	init(sql int, lcuuid string)
	reset(dbItem MPT, tool *tool.Tool)
}

type DiffBaseConstraint interface {
	Region | AZ | SubDomain | Host | VM |
		VPC | Network | Subnet | VRouter | RoutingTable |
		DHCPPort | VInterface | WANIP | LANIP | FloatingIP |
		NATGateway | NATRule | NATVMConnection | LB |
		LBListener | LBTargetServer | LBVMConnection | CEN |
		PeerConnection | RDSInstance | RedisInstance | PodCluster |
		PodNode | VMPodNodeConnection | PodNamespace | PodIngress |
		PodIngressRule | PodIngressRuleBackend | PodService |
		PodServicePort | PodGroup | ConfigMap | PodGroupConfigMapConnection |
		PodGroupPort | PodReplicaSet | Pod | Process | VIP

	GetSequence() int
	GetLcuuid() string
}
