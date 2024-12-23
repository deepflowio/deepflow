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
	MySQLItems[metadbmodel.Region]
}

type AZDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.AZ]
}

type SubDomainDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.SubDomain]
}

type HostDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Host]
}

type VMDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VM]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VMPodNodeConnection]
}

type VPCDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VPC]
}

type NetworkDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Network]
}

type SubnetDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Subnet]
}

type VRouterDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VRouter]
}

type RoutingTableDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RoutingTable]
}

type DHCPPortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.DHCPPort]
}

type VInterfaceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VInterface]
}

type FloatingIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.FloatingIP]
}

type LANIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LANIP]
}

type WANIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.WANIP]
}

type VIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VIP]
}

type NATGatewayDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATGateway]
}

type NATRuleDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATRule]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATVMConnection]
}

type LBDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LB]
}

type LBListenerDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBListener]
}

type LBTargetServerDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBTargetServer]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBVMConnection]
}

type PeerConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PeerConnection]
}

type CENDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.CEN]
}

type RDSInstanceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RDSInstance]
}

type RedisInstanceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RedisInstance]
}

type PodClusterDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodCluster]
}

type PodNamespaceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNamespace]
}

type PodNodeDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNode]
}

type PodIngressDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngress]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRule]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRuleBackend]
}

type PodServiceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodService]
}

type PodServicePortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodServicePort]
}

type PodGroupDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroup]
}

type PodGroupPortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroupPort]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodReplicaSet]
}

type PodDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Pod]
}

type ProcessDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Process]
}
