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
type MetadbItems[T metadbmodel.AssetResourceConstraint] struct {
	data []*T
}

func (m *MetadbItems[T]) GetMetadbItems() interface{} {
	return m.data
}

func (m *MetadbItems[T]) SetMetadbItems(items interface{}) {
	m.data = items.([]*T)
}

type DeletedRegions struct {
	Lcuuids
	MetadbItems[metadbmodel.Region]
	addition[DeleteNoneAddition]
}

type DeletedAZs struct {
	Lcuuids
	MetadbItems[metadbmodel.AZ]
	addition[DeleteNoneAddition]
}

type DeletedSubDomains struct {
	Lcuuids
	MetadbItems[metadbmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type DeletedHosts struct {
	Lcuuids
	MetadbItems[metadbmodel.Host]
	addition[DeleteNoneAddition]
}

type DeletedVMs struct {
	Lcuuids
	MetadbItems[metadbmodel.VM]
	addition[DeleteNoneAddition]
}

type DeletedVMPodNodeConnections struct {
	Lcuuids
	MetadbItems[metadbmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type DeletedVPCs struct {
	Lcuuids
	MetadbItems[metadbmodel.VPC]
	addition[DeleteNoneAddition]
}

type DeletedNetworks struct {
	Lcuuids
	MetadbItems[metadbmodel.Network]
	addition[DeleteNoneAddition]
}

type DeletedSubnets struct {
	Lcuuids
	MetadbItems[metadbmodel.Subnet]
	addition[DeleteNoneAddition]
}

type DeletedVRouters struct {
	Lcuuids
	MetadbItems[metadbmodel.VRouter]
	addition[DeleteNoneAddition]
}

type DeletedRoutingTables struct {
	Lcuuids
	MetadbItems[metadbmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DeletedDHCPPorts struct {
	Lcuuids
	MetadbItems[metadbmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type DeletedVInterfaces struct {
	Lcuuids
	MetadbItems[metadbmodel.VInterface]
	addition[DeleteNoneAddition]
}

type DeletedFloatingIPs struct {
	Lcuuids
	MetadbItems[metadbmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type DeletedLANIPs struct {
	Lcuuids
	MetadbItems[metadbmodel.LANIP]
	addition[DeleteNoneAddition]
}

type DeletedWANIPs struct {
	Lcuuids
	MetadbItems[metadbmodel.WANIP]
	addition[DeleteNoneAddition]
}

type DeletedVIPs struct {
	Lcuuids
	MetadbItems[metadbmodel.VIP]
	addition[DeleteNoneAddition]
}

type DeletedNATGateways struct {
	Lcuuids
	MetadbItems[metadbmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type DeletedNATRules struct {
	Lcuuids
	MetadbItems[metadbmodel.NATRule]
	addition[DeleteNoneAddition]
}

type DeletedNATVMConnections struct {
	Lcuuids
	MetadbItems[metadbmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedLBs struct {
	Lcuuids
	MetadbItems[metadbmodel.LB]
	addition[DeleteNoneAddition]
}

type DeletedLBListeners struct {
	Lcuuids
	MetadbItems[metadbmodel.LBListener]
	addition[DeleteNoneAddition]
}

type DeletedLBTargetServers struct {
	Lcuuids
	MetadbItems[metadbmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type DeletedLBVMConnections struct {
	Lcuuids
	MetadbItems[metadbmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedPeerConnections struct {
	Lcuuids
	MetadbItems[metadbmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type DeletedCENs struct {
	Lcuuids
	MetadbItems[metadbmodel.CEN]
	addition[DeleteNoneAddition]
}

type DeletedRDSInstances struct {
	Lcuuids
	MetadbItems[metadbmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type DeletedRedisInstances struct {
	Lcuuids
	MetadbItems[metadbmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type DeletedPodClusters struct {
	Lcuuids
	MetadbItems[metadbmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type DeletedPodNamespaces struct {
	Lcuuids
	MetadbItems[metadbmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type DeletedPodNodes struct {
	Lcuuids
	MetadbItems[metadbmodel.PodNode]
	addition[DeleteNoneAddition]
}

type DeletedPodIngresses struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRules struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRuleBackends struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type DeletedPodServices struct {
	Lcuuids
	MetadbItems[metadbmodel.PodService]
	addition[DeleteNoneAddition]
}

type DeletedPodServicePorts struct {
	Lcuuids
	MetadbItems[metadbmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type DeletedPodGroups struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type DeletedConfigMaps struct {
	Lcuuids
	MetadbItems[metadbmodel.ConfigMap]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupConfigMapConnections struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroupConfigMapConnection]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupPorts struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type DeletedPodReplicaSets struct {
	Lcuuids
	MetadbItems[metadbmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type DeletedPods struct {
	Lcuuids
	MetadbItems[metadbmodel.Pod]
	addition[DeleteNoneAddition]
}

type DeletedProcesses struct {
	Lcuuids
	MetadbItems[metadbmodel.Process]
	addition[ProcessDeleteAddition]
}

type ProcessDeleteAddition struct {
	DeletedGIDs []uint32
}

type DeletedCustomServices struct {
	Lcuuids
	MetadbItems[metadbmodel.CustomService]
	addition[DeleteNoneAddition]
}
