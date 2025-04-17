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

// TODO rename to metadb
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
	addition[DeleteNoneAddition]
}

type AZDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.AZ]
	addition[DeleteNoneAddition]
}

type SubDomainDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type HostDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Host]
	addition[DeleteNoneAddition]
}

type VMDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VM]
	addition[DeleteNoneAddition]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type VPCDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VPC]
	addition[DeleteNoneAddition]
}

type NetworkDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Network]
	addition[DeleteNoneAddition]
}

type SubnetDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Subnet]
	addition[DeleteNoneAddition]
}

type VRouterDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VRouter]
	addition[DeleteNoneAddition]
}

type RoutingTableDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DHCPPortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type VInterfaceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VInterface]
	addition[DeleteNoneAddition]
}

type FloatingIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type LANIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LANIP]
	addition[DeleteNoneAddition]
}

type WANIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.WANIP]
	addition[DeleteNoneAddition]
}

type VIPDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.VIP]
	addition[DeleteNoneAddition]
}

type NATGatewayDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type NATRuleDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATRule]
	addition[DeleteNoneAddition]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type LBDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LB]
	addition[DeleteNoneAddition]
}

type LBListenerDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBListener]
	addition[DeleteNoneAddition]
}

type LBTargetServerDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type PeerConnectionDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type CENDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.CEN]
	addition[DeleteNoneAddition]
}

type RDSInstanceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type RedisInstanceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type PodClusterDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type PodNamespaceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type PodNodeDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodNode]
	addition[DeleteNoneAddition]
}

type PodIngressDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type PodServiceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodService]
	addition[DeleteNoneAddition]
}

type PodServicePortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type PodGroupDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type PodGroupPortDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type PodDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Pod]
	addition[DeleteNoneAddition]
}

type ProcessDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.Process]
	addition[ProcessDeleteAddition]
}

type ProcessDeleteAddition struct {
	DeletedGIDs []uint32
}

type CustomServiceDelete struct {
	Lcuuids
	MySQLItems[mysqlmodel.CustomService]
	addition[DeleteNoneAddition]
}
