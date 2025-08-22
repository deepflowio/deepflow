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
	MySQLItems[metadbmodel.Region]
	addition[AddNoneAddition]
}

type AddedAZs struct {
	MySQLItems[metadbmodel.AZ]
	addition[AddNoneAddition]
}

type AddedSubDomains struct {
	MySQLItems[metadbmodel.SubDomain]
	addition[AddNoneAddition]
}

type AddedHosts struct {
	MySQLItems[metadbmodel.Host]
	addition[AddNoneAddition]
}

type AddedVMs struct {
	MySQLItems[metadbmodel.VM]
	addition[AddNoneAddition]
}

type AddedVMPodNodeConnections struct {
	MySQLItems[metadbmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type AddedVPCs struct {
	MySQLItems[metadbmodel.VPC]
	addition[AddNoneAddition]
}

type AddedNetworks struct {
	MySQLItems[metadbmodel.Network]
	addition[AddNoneAddition]
}

type AddedSubnets struct {
	MySQLItems[metadbmodel.Subnet]
	addition[AddNoneAddition]
}

type AddedVRouters struct {
	MySQLItems[metadbmodel.VRouter]
	addition[AddNoneAddition]
}

type AddedRoutingTables struct {
	MySQLItems[metadbmodel.RoutingTable]
	addition[AddNoneAddition]
}

type AddedDHCPPorts struct {
	MySQLItems[metadbmodel.DHCPPort]
	addition[AddNoneAddition]
}

type AddedVInterfaces struct {
	MySQLItems[metadbmodel.VInterface]
	addition[AddNoneAddition]
}

type AddedFloatingIPs struct {
	MySQLItems[metadbmodel.FloatingIP]
	addition[AddNoneAddition]
}

type AddedLANIPs struct {
	MySQLItems[metadbmodel.LANIP]
	addition[AddNoneAddition]
}

type AddedWANIPs struct {
	MySQLItems[metadbmodel.WANIP]
	addition[AddNoneAddition]
}

type AddedVIPs struct {
	MySQLItems[metadbmodel.VIP]
	addition[AddNoneAddition]
}

type AddedNATGateways struct {
	MySQLItems[metadbmodel.NATGateway]
	addition[AddNoneAddition]
}

type AddedNATRules struct {
	MySQLItems[metadbmodel.NATRule]
	addition[AddNoneAddition]
}

type AddedNATVMConnections struct {
	MySQLItems[metadbmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type AddedLBs struct {
	MySQLItems[metadbmodel.LB]
	addition[AddNoneAddition]
}

type AddedLBListeners struct {
	MySQLItems[metadbmodel.LBListener]
	addition[AddNoneAddition]
}

type AddedLBTargetServers struct {
	MySQLItems[metadbmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type AddedLBVMConnections struct {
	MySQLItems[metadbmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type AddedPeerConnections struct {
	MySQLItems[metadbmodel.PeerConnection]
	addition[AddNoneAddition]
}

type AddedCENs struct {
	MySQLItems[metadbmodel.CEN]
	addition[AddNoneAddition]
}

type AddedRDSInstances struct {
	MySQLItems[metadbmodel.RDSInstance]
	addition[AddNoneAddition]
}

type AddedRedisInstances struct {
	MySQLItems[metadbmodel.RedisInstance]
	addition[AddNoneAddition]
}

type AddedPodClusters struct {
	MySQLItems[metadbmodel.PodCluster]
	addition[AddNoneAddition]
}

type AddedPodNamespaces struct {
	MySQLItems[metadbmodel.PodNamespace]
	addition[AddNoneAddition]
}

type AddedPodNodes struct {
	MySQLItems[metadbmodel.PodNode]
	addition[AddNoneAddition]
}

type AddedPodIngresses struct {
	MySQLItems[metadbmodel.PodIngress]
	addition[AddNoneAddition]
}

type AddedPodIngressRules struct {
	MySQLItems[metadbmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type AddedPodIngressRuleBackends struct {
	MySQLItems[metadbmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type AddedPodServices struct {
	MySQLItems[metadbmodel.PodService]
	addition[AddNoneAddition]
}

type AddedPodServicePorts struct {
	MySQLItems[metadbmodel.PodServicePort]
	addition[AddNoneAddition]
}

type AddedPodGroups struct {
	MySQLItems[metadbmodel.PodGroup]
	addition[AddNoneAddition]
}

type AddedConfigMaps struct {
	MySQLItems[metadbmodel.ConfigMap]
	addition[AddNoneAddition]
}

type AddedPodGroupConfigMapConnections struct {
	MySQLItems[metadbmodel.PodGroupConfigMapConnection]
	addition[AddNoneAddition]
}

type AddedPodGroupPorts struct {
	MySQLItems[metadbmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type AddedPodReplicaSets struct {
	MySQLItems[metadbmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type AddedPods struct {
	MySQLItems[metadbmodel.Pod]
	addition[AddNoneAddition]
}

type AddedProcesses struct {
	MySQLItems[metadbmodel.Process]
	addition[AddedProcessesAddition]
}

type AddedProcessesAddition struct {
	// CreatedGIDs []uint32 // reserved for tagrecorder use
}

type AddedCustomServices struct {
	MySQLItems[metadbmodel.CustomService]
	addition[AddNoneAddition]
}
