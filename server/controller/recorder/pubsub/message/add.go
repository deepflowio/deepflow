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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type AddedRegions struct {
	MySQLItems[mysqlmodel.Region]
	addition[AddNoneAddition]
}

type AddedAZs struct {
	MySQLItems[mysqlmodel.AZ]
	addition[AddNoneAddition]
}

type AddedSubDomains struct {
	MySQLItems[mysqlmodel.SubDomain]
	addition[AddNoneAddition]
}

type AddedHosts struct {
	MySQLItems[mysqlmodel.Host]
	addition[AddNoneAddition]
}

type AddedVMs struct {
	MySQLItems[mysqlmodel.VM]
	addition[AddNoneAddition]
}

type AddedVMPodNodeConnections struct {
	MySQLItems[mysqlmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type AddedVPCs struct {
	MySQLItems[mysqlmodel.VPC]
	addition[AddNoneAddition]
}

type AddedNetworks struct {
	MySQLItems[mysqlmodel.Network]
	addition[AddNoneAddition]
}

type AddedSubnets struct {
	MySQLItems[mysqlmodel.Subnet]
	addition[AddNoneAddition]
}

type AddedVRouters struct {
	MySQLItems[mysqlmodel.VRouter]
	addition[AddNoneAddition]
}

type AddedRoutingTables struct {
	MySQLItems[mysqlmodel.RoutingTable]
	addition[AddNoneAddition]
}

type AddedDHCPPorts struct {
	MySQLItems[mysqlmodel.DHCPPort]
	addition[AddNoneAddition]
}

type AddedVInterfaces struct {
	MySQLItems[mysqlmodel.VInterface]
	addition[AddNoneAddition]
}

type AddedFloatingIPs struct {
	MySQLItems[mysqlmodel.FloatingIP]
	addition[AddNoneAddition]
}

type AddedLANIPs struct {
	MySQLItems[mysqlmodel.LANIP]
	addition[AddNoneAddition]
}

type AddedWANIPs struct {
	MySQLItems[mysqlmodel.WANIP]
	addition[AddNoneAddition]
}

type AddedVIPs struct {
	MySQLItems[mysqlmodel.VIP]
	addition[AddNoneAddition]
}

type AddedNATGateways struct {
	MySQLItems[mysqlmodel.NATGateway]
	addition[AddNoneAddition]
}

type AddedNATRules struct {
	MySQLItems[mysqlmodel.NATRule]
	addition[AddNoneAddition]
}

type AddedNATVMConnections struct {
	MySQLItems[mysqlmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type AddedLBs struct {
	MySQLItems[mysqlmodel.LB]
	addition[AddNoneAddition]
}

type AddedLBListeners struct {
	MySQLItems[mysqlmodel.LBListener]
	addition[AddNoneAddition]
}

type AddedLBTargetServers struct {
	MySQLItems[mysqlmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type AddedLBVMConnections struct {
	MySQLItems[mysqlmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type AddedPeerConnections struct {
	MySQLItems[mysqlmodel.PeerConnection]
	addition[AddNoneAddition]
}

type AddedCENs struct {
	MySQLItems[mysqlmodel.CEN]
	addition[AddNoneAddition]
}

type AddedRDSInstances struct {
	MySQLItems[mysqlmodel.RDSInstance]
	addition[AddNoneAddition]
}

type AddedRedisInstances struct {
	MySQLItems[mysqlmodel.RedisInstance]
	addition[AddNoneAddition]
}

type AddedPodClusters struct {
	MySQLItems[mysqlmodel.PodCluster]
	addition[AddNoneAddition]
}

type AddedPodNamespaces struct {
	MySQLItems[mysqlmodel.PodNamespace]
	addition[AddNoneAddition]
}

type AddedPodNodes struct {
	MySQLItems[mysqlmodel.PodNode]
	addition[AddNoneAddition]
}

type AddedPodIngresses struct {
	MySQLItems[mysqlmodel.PodIngress]
	addition[AddNoneAddition]
}

type AddedPodIngressRules struct {
	MySQLItems[mysqlmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type AddedPodIngressRuleBackends struct {
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type AddedPodServices struct {
	MySQLItems[mysqlmodel.PodService]
	addition[AddNoneAddition]
}

type AddedPodServicePorts struct {
	MySQLItems[mysqlmodel.PodServicePort]
	addition[AddNoneAddition]
}

type AddedPodGroups struct {
	MySQLItems[mysqlmodel.PodGroup]
	addition[AddNoneAddition]
}

type AddedConfigMaps struct {
	MySQLItems[mysqlmodel.ConfigMap]
	addition[AddNoneAddition]
}

type AddedPodGroupConfigMapConnections struct {
	MySQLItems[mysqlmodel.PodGroupConfigMapConnection]
	addition[AddNoneAddition]
}

type AddedPodGroupPorts struct {
	MySQLItems[mysqlmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type AddedPodReplicaSets struct {
	MySQLItems[mysqlmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type AddedPods struct {
	MySQLItems[mysqlmodel.Pod]
	addition[AddNoneAddition]
}

type AddedProcesses struct {
	MySQLItems[mysqlmodel.Process]
	addition[AddedProcessesAddition]
}

type AddedProcessesAddition struct {
	// CreatedGIDs []uint32 // reserved for tagrecorder use
}

type AddedCustomServices struct {
	MySQLItems[mysqlmodel.CustomService]
	addition[AddNoneAddition]
}
