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

type Lcuuids struct {
	data []string
}

func (d *Lcuuids) GetLcuuids() []string {
	return d.data
}

func (d *Lcuuids) SetLcuuids(lcuuids []string) {
	d.data = lcuuids
}

// TODO rename to metadb
type MySQLItems[T metadbmodel.AssetResourceConstraint] struct {
	data []*T
}

func (m *MySQLItems[T]) GetMySQLItems() interface{} {
	return m.data
}

func (m *MySQLItems[T]) SetMySQLItems(items interface{}) {
	m.data = items.([]*T)
}

type DeletedRegions struct {
	Lcuuids
	MySQLItems[metadbmodel.Region]
	addition[DeleteNoneAddition]
}

type DeletedAZs struct {
	Lcuuids
	MySQLItems[metadbmodel.AZ]
	addition[DeleteNoneAddition]
}

type DeletedSubDomains struct {
	Lcuuids
	MySQLItems[metadbmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type DeletedHosts struct {
	Lcuuids
	MySQLItems[metadbmodel.Host]
	addition[DeleteNoneAddition]
}

type DeletedVMs struct {
	Lcuuids
	MySQLItems[metadbmodel.VM]
	addition[DeleteNoneAddition]
}

type DeletedVMPodNodeConnections struct {
	Lcuuids
	MySQLItems[metadbmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type DeletedVPCs struct {
	Lcuuids
	MySQLItems[metadbmodel.VPC]
	addition[DeleteNoneAddition]
}

type DeletedNetworks struct {
	Lcuuids
	MySQLItems[metadbmodel.Network]
	addition[DeleteNoneAddition]
}

type DeletedSubnets struct {
	Lcuuids
	MySQLItems[metadbmodel.Subnet]
	addition[DeleteNoneAddition]
}

type DeletedVRouters struct {
	Lcuuids
	MySQLItems[metadbmodel.VRouter]
	addition[DeleteNoneAddition]
}

type DeletedRoutingTables struct {
	Lcuuids
	MySQLItems[metadbmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DeletedDHCPPorts struct {
	Lcuuids
	MySQLItems[metadbmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type DeletedVInterfaces struct {
	Lcuuids
	MySQLItems[metadbmodel.VInterface]
	addition[DeleteNoneAddition]
}

type DeletedFloatingIPs struct {
	Lcuuids
	MySQLItems[metadbmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type DeletedLANIPs struct {
	Lcuuids
	MySQLItems[metadbmodel.LANIP]
	addition[DeleteNoneAddition]
}

type DeletedWANIPs struct {
	Lcuuids
	MySQLItems[metadbmodel.WANIP]
	addition[DeleteNoneAddition]
}

type DeletedVIPs struct {
	Lcuuids
	MySQLItems[metadbmodel.VIP]
	addition[DeleteNoneAddition]
}

type DeletedNATGateways struct {
	Lcuuids
	MySQLItems[metadbmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type DeletedNATRules struct {
	Lcuuids
	MySQLItems[metadbmodel.NATRule]
	addition[DeleteNoneAddition]
}

type DeletedNATVMConnections struct {
	Lcuuids
	MySQLItems[metadbmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedLBs struct {
	Lcuuids
	MySQLItems[metadbmodel.LB]
	addition[DeleteNoneAddition]
}

type DeletedLBListeners struct {
	Lcuuids
	MySQLItems[metadbmodel.LBListener]
	addition[DeleteNoneAddition]
}

type DeletedLBTargetServers struct {
	Lcuuids
	MySQLItems[metadbmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type DeletedLBVMConnections struct {
	Lcuuids
	MySQLItems[metadbmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedPeerConnections struct {
	Lcuuids
	MySQLItems[metadbmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type DeletedCENs struct {
	Lcuuids
	MySQLItems[metadbmodel.CEN]
	addition[DeleteNoneAddition]
}

type DeletedRDSInstances struct {
	Lcuuids
	MySQLItems[metadbmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type DeletedRedisInstances struct {
	Lcuuids
	MySQLItems[metadbmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type DeletedPodClusters struct {
	Lcuuids
	MySQLItems[metadbmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type DeletedPodNamespaces struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type DeletedPodNodes struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNode]
	addition[DeleteNoneAddition]
}

type DeletedPodIngresses struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRules struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRuleBackends struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type DeletedPodServices struct {
	Lcuuids
	MySQLItems[metadbmodel.PodService]
	addition[DeleteNoneAddition]
}

type DeletedPodServicePorts struct {
	Lcuuids
	MySQLItems[metadbmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type DeletedPodGroups struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type DeletedConfigMaps struct {
	Lcuuids
	MySQLItems[metadbmodel.ConfigMap]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupConfigMapConnections struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroupConfigMapConnection]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupPorts struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type DeletedPodReplicaSets struct {
	Lcuuids
	MySQLItems[metadbmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type DeletedPods struct {
	Lcuuids
	MySQLItems[metadbmodel.Pod]
	addition[DeleteNoneAddition]
}

type DeletedProcesses struct {
	Lcuuids
	MySQLItems[metadbmodel.Process]
	addition[DeletedProcessesAddition]
}

type DeletedProcessesAddition struct {
	DeletedGIDs []uint32
}

type DeletedCustomServices struct {
	Lcuuids
	MySQLItems[metadbmodel.CustomService]
	addition[DeleteNoneAddition]
}
