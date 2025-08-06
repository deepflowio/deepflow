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

package message

import (
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type AddedRegions struct {
	MetadbItems[metadbmodel.Region]
	addition[AddNoneAddition]
}

type AddedAZs struct {
	MetadbItems[metadbmodel.AZ]
	addition[AddNoneAddition]
}

type AddedSubDomains struct {
	MetadbItems[metadbmodel.SubDomain]
	addition[AddNoneAddition]
}

type AddedHosts struct {
	MetadbItems[metadbmodel.Host]
	addition[AddNoneAddition]
}

type AddedVMs struct {
	MetadbItems[metadbmodel.VM]
	addition[AddNoneAddition]
}

type AddedVMPodNodeConnections struct {
	MetadbItems[metadbmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type AddedVPCs struct {
	MetadbItems[metadbmodel.VPC]
	addition[AddNoneAddition]
}

type AddedNetworks struct {
	MetadbItems[metadbmodel.Network]
	addition[AddNoneAddition]
}

type AddedSubnets struct {
	MetadbItems[metadbmodel.Subnet]
	addition[AddNoneAddition]
}

type AddedVRouters struct {
	MetadbItems[metadbmodel.VRouter]
	addition[AddNoneAddition]
}

type AddedRoutingTables struct {
	MetadbItems[metadbmodel.RoutingTable]
	addition[AddNoneAddition]
}

type AddedDHCPPorts struct {
	MetadbItems[metadbmodel.DHCPPort]
	addition[AddNoneAddition]
}

type AddedVInterfaces struct {
	MetadbItems[metadbmodel.VInterface]
	addition[AddNoneAddition]
}

type AddedFloatingIPs struct {
	MetadbItems[metadbmodel.FloatingIP]
	addition[AddNoneAddition]
}

type AddedLANIPs struct {
	MetadbItems[metadbmodel.LANIP]
	addition[AddNoneAddition]
}

type AddedWANIPs struct {
	MetadbItems[metadbmodel.WANIP]
	addition[AddNoneAddition]
}

type AddedVIPs struct {
	MetadbItems[metadbmodel.VIP]
	addition[AddNoneAddition]
}

type AddedNATGateways struct {
	MetadbItems[metadbmodel.NATGateway]
	addition[AddNoneAddition]
}

type AddedNATRules struct {
	MetadbItems[metadbmodel.NATRule]
	addition[AddNoneAddition]
}

type AddedNATVMConnections struct {
	MetadbItems[metadbmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type AddedLBs struct {
	MetadbItems[metadbmodel.LB]
	addition[AddNoneAddition]
}

type AddedLBListeners struct {
	MetadbItems[metadbmodel.LBListener]
	addition[AddNoneAddition]
}

type AddedLBTargetServers struct {
	MetadbItems[metadbmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type AddedLBVMConnections struct {
	MetadbItems[metadbmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type AddedPeerConnections struct {
	MetadbItems[metadbmodel.PeerConnection]
	addition[AddNoneAddition]
}

type AddedCENs struct {
	MetadbItems[metadbmodel.CEN]
	addition[AddNoneAddition]
}

type AddedRDSInstances struct {
	MetadbItems[metadbmodel.RDSInstance]
	addition[AddNoneAddition]
}

type AddedRedisInstances struct {
	MetadbItems[metadbmodel.RedisInstance]
	addition[AddNoneAddition]
}

type AddedPodClusters struct {
	MetadbItems[metadbmodel.PodCluster]
	addition[AddNoneAddition]
}

type AddedPodNamespaces struct {
	MetadbItems[metadbmodel.PodNamespace]
	addition[AddNoneAddition]
}

type AddedPodNodes struct {
	MetadbItems[metadbmodel.PodNode]
	addition[AddNoneAddition]
}

type AddedPodIngresses struct {
	MetadbItems[metadbmodel.PodIngress]
	addition[AddNoneAddition]
}

type AddedPodIngressRules struct {
	MetadbItems[metadbmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type AddedPodIngressRuleBackends struct {
	MetadbItems[metadbmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type AddedPodServices struct {
	MetadbItems[metadbmodel.PodService]
	addition[AddNoneAddition]
}

type AddedPodServicePorts struct {
	MetadbItems[metadbmodel.PodServicePort]
	addition[AddNoneAddition]
}

type AddedPodGroups struct {
	MetadbItems[metadbmodel.PodGroup]
	addition[AddNoneAddition]
}

type AddedConfigMaps struct {
	MetadbItems[metadbmodel.ConfigMap]
	addition[AddNoneAddition]
}

type AddedPodGroupConfigMapConnections struct {
	MetadbItems[metadbmodel.PodGroupConfigMapConnection]
	addition[AddNoneAddition]
}

type AddedPodGroupPorts struct {
	MetadbItems[metadbmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type AddedPodReplicaSets struct {
	MetadbItems[metadbmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type AddedPods struct {
	MetadbItems[metadbmodel.Pod]
	addition[AddNoneAddition]
}

type AddedProcesses struct {
	MetadbItems[metadbmodel.Process]
	addition[ProcessAddAddition]
}

type ProcessAddAddition struct {
	// CreatedGIDs []uint32 // reserved for tagrecorder use
}

type AddedCustomServices struct {
	MetadbItems[metadbmodel.CustomService]
	addition[AddNoneAddition]
}
