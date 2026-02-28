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
	message.AddedRegions | message.AddedAzs | message.AddedSubDomains | message.AddedHosts | message.AddedVms |
		message.AddedVpcs | message.AddedNetworks | message.AddedSubnets | message.AddedVrouters | message.AddedRoutingTables |
		message.AddedDhcpPorts | message.AddedVinterfaces | message.AddedWanIps | message.AddedLanIps | message.AddedFloatingIps |
		message.AddedNatGateways | message.AddedNatRules | message.AddedNatVmConnections | message.AddedLbs |
		message.AddedLbListeners | message.AddedLbTargetServers | message.AddedLbVmConnections | message.AddedCens |
		message.AddedPeerConnections | message.AddedRdsInstances | message.AddedRedisInstances | message.AddedPodClusters |
		message.AddedPodNodes | message.AddedVmPodNodeConnections | message.AddedPodNamespaces | message.AddedPodIngresses |
		message.AddedPodIngressRules | message.AddedPodIngressRuleBackends | message.AddedPodServices |
		message.AddedPodServicePorts | message.AddedPodGroups | message.AddedConfigMaps | message.AddedPodGroupConfigMapConnections |
		message.AddedPodGroupPorts | message.AddedPodReplicaSets | message.AddedPods | message.AddedProcesses | message.AddedVips | message.AddedCustomServices
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
	message.UpdatedRegion | message.UpdatedAz | message.UpdatedSubDomain | message.UpdatedHost | message.UpdatedVm |
		message.UpdatedVpc | message.UpdatedNetwork | message.UpdatedSubnet | message.UpdatedVrouter | message.UpdatedRoutingTable |
		message.UpdatedDhcpPort | message.UpdatedVinterface | message.UpdatedWanIp | message.UpdatedLanIp | message.UpdatedFloatingIp |
		message.UpdatedNatGateway | message.UpdatedNatRule | message.UpdatedNatVmConnection | message.UpdatedLb |
		message.UpdatedLbListener | message.UpdatedLbTargetServer | message.UpdatedLbVmConnection | message.UpdatedCen |
		message.UpdatedPeerConnection | message.UpdatedRdsInstance | message.UpdatedRedisInstance | message.UpdatedPodCluster |
		message.UpdatedPodNode | message.UpdatedVmPodNodeConnection | message.UpdatedPodNamespace | message.UpdatedPodIngress |
		message.UpdatedPodIngressRule | message.UpdatedPodIngressRuleBackend | message.UpdatedPodService |
		message.UpdatedPodServicePort | message.UpdatedPodGroup | message.UpdatedConfigMap | message.UpdatedPodGroupConfigMapConnection |
		message.UpdatedPodGroupPort | message.UpdatedPodReplicaSet | message.UpdatedPod | message.UpdatedProcess | message.UpdatedVip | message.UpdatedCustomService
}

type FieldsUpdatePtr[T FieldsUpdate] interface {
	*T

	SetID(int)
	GetID() int
	SetLcuuid(string)
	GetLcuuid() string
}

type FieldsUpdate interface {
	message.UpdatedRegionFields | message.UpdatedAzFields | message.UpdatedSubDomainFields | message.UpdatedHostFields |
		message.UpdatedVmFields | message.UpdatedVpcFields | message.UpdatedNetworkFields | message.UpdatedSubnetFields |
		message.UpdatedVrouterFields | message.UpdatedRoutingTableFields | message.UpdatedDhcpPortFields |
		message.UpdatedVinterfaceFields | message.UpdatedWanIpFields | message.UpdatedLanIpFields | message.UpdatedFloatingIpFields |
		message.UpdatedNatGatewayFields | message.UpdatedNatRuleFields | message.UpdatedNatVmConnectionFields | message.UpdatedLbFields |
		message.UpdatedLbListenerFields | message.UpdatedLbTargetServerFields | message.UpdatedLbVmConnectionFields | message.UpdatedCenFields |
		message.UpdatedPeerConnectionFields | message.UpdatedRdsInstanceFields | message.UpdatedRedisInstanceFields | message.UpdatedPodClusterFields |
		message.UpdatedPodNodeFields | message.UpdatedVmPodNodeConnectionFields | message.UpdatedPodNamespaceFields | message.UpdatedPodIngressFields |
		message.UpdatedPodIngressRuleFields | message.UpdatedPodIngressRuleBackendFields | message.UpdatedPodServiceFields |
		message.UpdatedPodServicePortFields | message.UpdatedPodGroupFields | message.UpdatedConfigMapFields |
		message.UpdatedPodGroupConfigMapConnectionFields | message.UpdatedPodGroupPortFields | message.UpdatedPodReplicaSetFields |
		message.UpdatedPodFields | message.UpdatedProcessFields | message.UpdatedVipFields | message.UpdatedCustomServiceFields
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
	message.DeletedRegions | message.DeletedAzs | message.DeletedSubDomains | message.DeletedHosts | message.DeletedVms |
		message.DeletedVpcs | message.DeletedNetworks | message.DeletedSubnets | message.DeletedVrouters | message.DeletedRoutingTables |
		message.DeletedDhcpPorts | message.DeletedVinterfaces | message.DeletedWanIps | message.DeletedLanIps | message.DeletedFloatingIps |
		message.DeletedNatGateways | message.DeletedNatRules | message.DeletedNatVmConnections | message.DeletedLbs |
		message.DeletedLbListeners | message.DeletedLbTargetServers | message.DeletedLbVmConnections | message.DeletedCens |
		message.DeletedPeerConnections | message.DeletedRdsInstances | message.DeletedRedisInstances | message.DeletedPodClusters |
		message.DeletedPodNodes | message.DeletedVmPodNodeConnections | message.DeletedPodNamespaces | message.DeletedPodIngresses |
		message.DeletedPodIngressRules | message.DeletedPodIngressRuleBackends | message.DeletedPodServices |
		message.DeletedPodServicePorts | message.DeletedPodGroups | message.DeletedConfigMaps | message.DeletedPodGroupConfigMapConnections |
		message.DeletedPodGroupPorts | message.DeletedPodReplicaSets | message.DeletedPods | message.DeletedProcesses | message.DeletedVips | message.DeletedCustomServices
}
