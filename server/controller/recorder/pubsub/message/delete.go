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

type MySQLItems[T constraint.MySQLModel] struct {
	data []*T
}

func (m *MySQLItems[T]) GetMySQLItems() interface{} {
	return m.data
}

func (m *MySQLItems[T]) SetMySQLItems(items interface{}) {
	m.data = items.([]*T)
}

type RegionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Region]
}

type AZDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.AZ]
}

type SubDomainDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.SubDomain]
}

type HostDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Host]
}

type VMDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VM]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VMPodNodeConnection]
}

type VPCDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VPC]
}

type NetworkDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Network]
}

type SubnetDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Subnet]
}

type VRouterDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VRouter]
}

type RoutingTableDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RoutingTable]
}

type DHCPPortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.DHCPPort]
}

type VInterfaceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VInterface]
}

type FloatingIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.FloatingIP]
}

type LANIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LANIP]
}

type WANIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.WANIP]
}

type VIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VIP]
}

type NATGatewayDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATGateway]
}

type NATRuleDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATRule]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATVMConnection]
}

type LBDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LB]
}

type LBListenerDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBListener]
}

type LBTargetServerDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBTargetServer]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBVMConnection]
}

type PeerConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PeerConnection]
}

type CENDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.CEN]
}

type RDSInstanceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RDSInstance]
}

type RedisInstanceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RedisInstance]
}

type PodClusterDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodCluster]
}

type PodNamespaceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNamespace]
}

type PodNodeDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNode]
}

type PodIngressDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngress]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRule]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
}

type PodServiceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodService]
}

type PodServicePortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodServicePort]
}

type PodGroupDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroup]
}

type PodGroupPortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroupPort]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodReplicaSet]
}

type PodDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Pod]
}

type ProcessDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Process]
}

type CustomServiceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.CustomService]
}
