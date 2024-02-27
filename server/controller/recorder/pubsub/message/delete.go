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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
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
	MySQLItems[mysql.Region]
}

type AZDelete struct {
	Lcuuids
	MySQLItems[mysql.AZ]
}

type SubDomainDelete struct {
	Lcuuids
	MySQLItems[mysql.SubDomain]
}

type HostDelete struct {
	Lcuuids
	MySQLItems[mysql.Host]
}

type VMDelete struct {
	Lcuuids
	MySQLItems[mysql.VM]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MySQLItems[mysql.VMPodNodeConnection]
}

type VPCDelete struct {
	Lcuuids
	MySQLItems[mysql.VPC]
}

type NetworkDelete struct {
	Lcuuids
	MySQLItems[mysql.Network]
}

type SubnetDelete struct {
	Lcuuids
	MySQLItems[mysql.Subnet]
}

type VRouterDelete struct {
	Lcuuids
	MySQLItems[mysql.VRouter]
}

type RoutingTableDelete struct {
	Lcuuids
	MySQLItems[mysql.RoutingTable]
}

type DHCPPortDelete struct {
	Lcuuids
	MySQLItems[mysql.DHCPPort]
}

type VInterfaceDelete struct {
	Lcuuids
	MySQLItems[mysql.VInterface]
}

type FloatingIPDelete struct {
	Lcuuids
	MySQLItems[mysql.FloatingIP]
}

type LANIPDelete struct {
	Lcuuids
	MySQLItems[mysql.LANIP]
}

type WANIPDelete struct {
	Lcuuids
	MySQLItems[mysql.WANIP]
}

type VIPDelete struct {
	Lcuuids
	MySQLItems[mysql.VIP]
}

type SecurityGroupDelete struct {
	Lcuuids
	MySQLItems[mysql.SecurityGroup]
}

type SecurityGroupRuleDelete struct {
	Lcuuids
	MySQLItems[mysql.SecurityGroupRule]
}

type VMSecurityGroupDelete struct {
	Lcuuids
	MySQLItems[mysql.VMSecurityGroup]
}

type NATGatewayDelete struct {
	Lcuuids
	MySQLItems[mysql.NATGateway]
}

type NATRuleDelete struct {
	Lcuuids
	MySQLItems[mysql.NATRule]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysql.NATVMConnection]
}

type LBDelete struct {
	Lcuuids
	MySQLItems[mysql.LB]
}

type LBListenerDelete struct {
	Lcuuids
	MySQLItems[mysql.LBListener]
}

type LBTargetServerDelete struct {
	Lcuuids
	MySQLItems[mysql.LBTargetServer]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysql.LBVMConnection]
}

type PeerConnectionDelete struct {
	Lcuuids
	MySQLItems[mysql.PeerConnection]
}

type CENDelete struct {
	Lcuuids
	MySQLItems[mysql.CEN]
}

type RDSInstanceDelete struct {
	Lcuuids
	MySQLItems[mysql.RDSInstance]
}

type RedisInstanceDelete struct {
	Lcuuids
	MySQLItems[mysql.RedisInstance]
}

type PodClusterDelete struct {
	Lcuuids
	MySQLItems[mysql.PodCluster]
}

type PodNamespaceDelete struct {
	Lcuuids
	MySQLItems[mysql.PodNamespace]
}

type PodNodeDelete struct {
	Lcuuids
	MySQLItems[mysql.PodNode]
}

type PodIngressDelete struct {
	Lcuuids
	MySQLItems[mysql.PodIngress]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MySQLItems[mysql.PodIngressRule]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MySQLItems[mysql.PodIngressRuleBackend]
}

type PodServiceDelete struct {
	Lcuuids
	MySQLItems[mysql.PodService]
}

type PodServicePortDelete struct {
	Lcuuids
	MySQLItems[mysql.PodServicePort]
}

type PodGroupDelete struct {
	Lcuuids
	MySQLItems[mysql.PodGroup]
}

type PodGroupPortDelete struct {
	Lcuuids
	MySQLItems[mysql.PodGroupPort]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MySQLItems[mysql.PodReplicaSet]
}

type PodDelete struct {
	Lcuuids
	MySQLItems[mysql.Pod]
}

type ProcessDelete struct {
	Lcuuids
	MySQLItems[mysql.Process]
}

type PrometheusTargetDelete struct {
	Lcuuids
	MySQLItems[mysql.PrometheusTarget]
}
