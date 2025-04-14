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
	MySQLItems[metadbmodel.Region]
	addition[DeleteNoneAddition]
}

type AZDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.AZ]
	addition[DeleteNoneAddition]
}

type SubDomainDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type HostDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Host]
	addition[DeleteNoneAddition]
}

type VMDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VM]
	addition[DeleteNoneAddition]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type VPCDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VPC]
	addition[DeleteNoneAddition]
}

type NetworkDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Network]
	addition[DeleteNoneAddition]
}

type SubnetDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Subnet]
	addition[DeleteNoneAddition]
}

type VRouterDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VRouter]
	addition[DeleteNoneAddition]
}

type RoutingTableDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DHCPPortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type VInterfaceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VInterface]
	addition[DeleteNoneAddition]
}

type FloatingIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type LANIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LANIP]
	addition[DeleteNoneAddition]
}

type WANIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.WANIP]
	addition[DeleteNoneAddition]
}

type VIPDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.VIP]
	addition[DeleteNoneAddition]
}

type NATGatewayDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type NATRuleDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATRule]
	addition[DeleteNoneAddition]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type LBDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LB]
	addition[DeleteNoneAddition]
}

type LBListenerDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBListener]
	addition[DeleteNoneAddition]
}

type LBTargetServerDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type PeerConnectionDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type CENDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.CEN]
	addition[DeleteNoneAddition]
}

type RDSInstanceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type RedisInstanceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type PodClusterDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type PodNamespaceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type PodNodeDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodNode]
	addition[DeleteNoneAddition]
}

type PodIngressDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type PodServiceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodService]
	addition[DeleteNoneAddition]
}

type PodServicePortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type PodGroupDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type PodGroupPortDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type PodDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Pod]
	addition[DeleteNoneAddition]
}

type ProcessDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.Process]
	addition[ProcessDeleteAddition]
}

type ProcessDeleteAddition struct {
	DeletedGIDs []uint64
}

type CustomServiceDelete struct {
	Lcuuids
	MySQLItems[metadbmodel.CustomService]
	addition[DeleteNoneAddition]
}
