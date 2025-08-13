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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
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

// TODO rename to mysql
type MySQLItems[T constraint.MySQLModel] struct {
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
	MySQLItems[mysqlmodel.Region]
	addition[DeleteNoneAddition]
}

type DeletedAZs struct {
	Lcuuids
	MySQLItems[mysqlmodel.AZ]
	addition[DeleteNoneAddition]
}

type DeletedSubDomains struct {
	Lcuuids
	MySQLItems[mysqlmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type DeletedHosts struct {
	Lcuuids
	MySQLItems[mysqlmodel.Host]
	addition[DeleteNoneAddition]
}

type DeletedVMs struct {
	Lcuuids
	MySQLItems[mysqlmodel.VM]
	addition[DeleteNoneAddition]
}

type DeletedVMPodNodeConnections struct {
	Lcuuids
	MySQLItems[mysqlmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type DeletedVPCs struct {
	Lcuuids
	MySQLItems[mysqlmodel.VPC]
	addition[DeleteNoneAddition]
}

type DeletedNetworks struct {
	Lcuuids
	MySQLItems[mysqlmodel.Network]
	addition[DeleteNoneAddition]
}

type DeletedSubnets struct {
	Lcuuids
	MySQLItems[mysqlmodel.Subnet]
	addition[DeleteNoneAddition]
}

type DeletedVRouters struct {
	Lcuuids
	MySQLItems[mysqlmodel.VRouter]
	addition[DeleteNoneAddition]
}

type DeletedRoutingTables struct {
	Lcuuids
	MySQLItems[mysqlmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DeletedDHCPPorts struct {
	Lcuuids
	MySQLItems[mysqlmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type DeletedVInterfaces struct {
	Lcuuids
	MySQLItems[mysqlmodel.VInterface]
	addition[DeleteNoneAddition]
}

type DeletedFloatingIPs struct {
	Lcuuids
	MySQLItems[mysqlmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type DeletedLANIPs struct {
	Lcuuids
	MySQLItems[mysqlmodel.LANIP]
	addition[DeleteNoneAddition]
}

type DeletedWANIPs struct {
	Lcuuids
	MySQLItems[mysqlmodel.WANIP]
	addition[DeleteNoneAddition]
}

type DeletedVIPs struct {
	Lcuuids
	MySQLItems[mysqlmodel.VIP]
	addition[DeleteNoneAddition]
}

type DeletedNATGateways struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type DeletedNATRules struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATRule]
	addition[DeleteNoneAddition]
}

type DeletedNATVMConnections struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedLBs struct {
	Lcuuids
	MySQLItems[mysqlmodel.LB]
	addition[DeleteNoneAddition]
}

type DeletedLBListeners struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBListener]
	addition[DeleteNoneAddition]
}

type DeletedLBTargetServers struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type DeletedLBVMConnections struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type DeletedPeerConnections struct {
	Lcuuids
	MySQLItems[mysqlmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type DeletedCENs struct {
	Lcuuids
	MySQLItems[mysqlmodel.CEN]
	addition[DeleteNoneAddition]
}

type DeletedRDSInstances struct {
	Lcuuids
	MySQLItems[mysqlmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type DeletedRedisInstances struct {
	Lcuuids
	MySQLItems[mysqlmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type DeletedPodClusters struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type DeletedPodNamespaces struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type DeletedPodNodes struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNode]
	addition[DeleteNoneAddition]
}

type DeletedPodIngresses struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRules struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type DeletedPodIngressRuleBackends struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type DeletedPodServices struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodService]
	addition[DeleteNoneAddition]
}

type DeletedPodServicePorts struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type DeletedPodGroups struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type DeletedConfigMaps struct {
	Lcuuids
	MySQLItems[mysqlmodel.ConfigMap]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupConfigMapConnections struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroupConfigMapConnection]
	addition[DeleteNoneAddition]
}

type DeletedPodGroupPorts struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type DeletedPodReplicaSets struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type DeletedPods struct {
	Lcuuids
	MySQLItems[mysqlmodel.Pod]
	addition[DeleteNoneAddition]
}

type DeletedProcesses struct {
	Lcuuids
	MySQLItems[mysqlmodel.Process]
	addition[DeletedProcessesAddition]
}

type DeletedProcessesAddition struct {
	DeletedGIDs []uint32
}

type DeletedCustomServices struct {
	Lcuuids
	MySQLItems[mysqlmodel.CustomService]
	addition[DeleteNoneAddition]
}
