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

package constraint

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type AddPtr[T Add] interface {
	*T

	SetMetadbItems(interface{})
	GetMetadbItems() interface{} // return []*constraint.MetadbModel
	SetAddition(interface{})
	GetAddition() interface{} // return *message.Addition
}

type Add interface {
	message.AddedRegions | message.AddedAZs | message.AddedSubDomains | message.AddedHosts | message.AddedVMs |
		message.AddedVPCs | message.AddedNetworks | message.AddedSubnets | message.AddedVRouters | message.AddedRoutingTables |
		message.AddedDHCPPorts | message.AddedVInterfaces | message.AddedWANIPs | message.AddedLANIPs | message.AddedFloatingIPs |
		message.AddedNATGateways | message.AddedNATRules | message.AddedNATVMConnections | message.AddedLBs |
		message.AddedLBListeners | message.AddedLBTargetServers | message.AddedLBVMConnections | message.AddedCENs |
		message.AddedPeerConnections | message.AddedRDSInstances | message.AddedRedisInstances | message.AddedPodClusters |
		message.AddedPodNodes | message.AddedVMPodNodeConnections | message.AddedPodNamespaces | message.AddedPodIngresses |
		message.AddedPodIngressRules | message.AddedPodIngressRuleBackends | message.AddedPodServices |
		message.AddedPodServicePorts | message.AddedPodGroups | message.AddedConfigMaps | message.AddedPodGroupConfigMapConnections |
		message.AddedPodGroupPorts | message.AddedPodReplicaSets | message.AddedPods | message.AddedProcesses | message.AddedVIPs | message.AddedCustomServices
}

type UpdatePtr[T Update] interface {
	*T

	SetFields(interface{})
	GetFields() interface{} // return *FieldsUpdate
	SetNewMetadbItem(interface{})
	GetNewMetadbItem() interface{} // return *constraint.MetadbModel
}

// Update是所有资源更新消息的泛型约束
type Update interface {
	message.UpdatedRegion | message.UpdatedAZ | message.UpdatedSubDomain | message.UpdatedHost | message.UpdatedVM |
		message.UpdatedVPC | message.UpdatedNetwork | message.UpdatedSubnet | message.UpdatedVRouter | message.UpdatedRoutingTable |
		message.UpdatedDHCPPort | message.UpdatedVInterface | message.UpdatedWANIP | message.UpdatedLANIP | message.UpdatedFloatingIP |
		message.UpdatedNATGateway | message.UpdatedNATRule | message.UpdatedNATVMConnection | message.UpdatedLB |
		message.UpdatedLBListener | message.UpdatedLBTargetServer | message.UpdatedLBVMConnection | message.UpdatedCEN |
		message.UpdatedPeerConnection | message.UpdatedRDSInstance | message.UpdatedRedisInstance | message.UpdatedPodCluster |
		message.UpdatedPodNode | message.UpdatedVMPodNodeConnection | message.UpdatedPodNamespace | message.UpdatedPodIngress |
		message.UpdatedPodIngressRule | message.UpdatedPodIngressRuleBackend | message.UpdatedPodService |
		message.UpdatedPodServicePort | message.UpdatedPodGroup | message.UpdatedConfigMap | message.UpdatedPodGroupConfigMapConnection |
		message.UpdatedPodGroupPort | message.UpdatedPodReplicaSet | message.UpdatedPod | message.UpdatedProcess | message.UpdatedVIP | message.UpdatedCustomService
}

type FieldsUpdatePtr[T FieldsUpdate] interface {
	*T

	SetID(int)
	GetID() int
	SetLcuuid(string)
	GetLcuuid() string
}

type FieldsUpdate interface {
	message.UpdatedRegionFields | message.UpdatedAZFields | message.UpdatedSubDomainFields | message.UpdatedHostFields |
		message.UpdatedVMFields | message.UpdatedVPCFields | message.UpdatedNetworkFields | message.UpdatedSubnetFields |
		message.UpdatedVRouterFields | message.UpdatedRoutingTableFields | message.UpdatedDHCPPortFields |
		message.UpdatedVInterfaceFields | message.UpdatedWANIPFields | message.UpdatedLANIPFields | message.UpdatedFloatingIPFields |
		message.UpdatedNATGatewayFields | message.UpdatedNATRuleFields | message.UpdatedNATVMConnectionFields | message.UpdatedLBFields |
		message.UpdatedLBListenerFields | message.UpdatedLBTargetServerFields | message.UpdatedLBVMConnectionFields | message.UpdatedCENFields |
		message.UpdatedPeerConnectionFields | message.UpdatedRDSInstanceFields | message.UpdatedRedisInstanceFields | message.UpdatedPodClusterFields |
		message.UpdatedPodNodeFields | message.UpdatedVMPodNodeConnectionFields | message.UpdatedPodNamespaceFields | message.UpdatedPodIngressFields |
		message.UpdatedPodIngressRuleFields | message.UpdatedPodIngressRuleBackendFields | message.UpdatedPodServiceFields |
		message.UpdatedPodServicePortFields | message.UpdatedPodGroupFields | message.UpdatedConfigMapFields |
		message.UpdatedPodGroupConfigMapConnectionFields | message.UpdatedPodGroupPortFields | message.UpdatedPodReplicaSetFields |
		message.UpdatedPodFields | message.UpdatedProcessFields | message.UpdatedVIPFields | message.UpdatedCustomServiceFields
}

type DeletePtr[T Delete] interface {
	*T

	SetLcuuids([]string)
	GetLcuuids() []string
	SetMetadbItems(interface{})
	GetMetadbItems() interface{} // return []*constraint.MetadbModel
	SetAddition(interface{})
	GetAddition() interface{} // return *constraint.Addition
}

type Delete interface {
	message.DeletedRegions | message.DeletedAZs | message.DeletedSubDomains | message.DeletedHosts | message.DeletedVMs |
		message.DeletedVPCs | message.DeletedNetworks | message.DeletedSubnets | message.DeletedVRouters | message.DeletedRoutingTables |
		message.DeletedDHCPPorts | message.DeletedVInterfaces | message.DeletedWANIPs | message.DeletedLANIPs | message.DeletedFloatingIPs |
		message.DeletedNATGateways | message.DeletedNATRules | message.DeletedNATVMConnections | message.DeletedLBs |
		message.DeletedLBListeners | message.DeletedLBTargetServers | message.DeletedLBVMConnections | message.DeletedCENs |
		message.DeletedPeerConnections | message.DeletedRDSInstances | message.DeletedRedisInstances | message.DeletedPodClusters |
		message.DeletedPodNodes | message.DeletedVMPodNodeConnections | message.DeletedPodNamespaces | message.DeletedPodIngresses |
		message.DeletedPodIngressRules | message.DeletedPodIngressRuleBackends | message.DeletedPodServices |
		message.DeletedPodServicePorts | message.DeletedPodGroups | message.DeletedConfigMaps | message.DeletedPodGroupConfigMapConnections |
		message.DeletedPodGroupPorts | message.DeletedPodReplicaSets | message.DeletedPods | message.DeletedProcesses | message.DeletedVIPs | message.DeletedCustomServices
}
