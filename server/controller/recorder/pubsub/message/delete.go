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
type MetadbItems[T constraint.MetadbModel] struct {
	data []*T
}

func (m *MetadbItems[T]) GetMetadbItems() interface{} {
	return m.data
}

func (m *MetadbItems[T]) SetMetadbItems(items interface{}) {
	m.data = items.([]*T)
}

type RegionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Region]
	addition[DeleteNoneAddition]
}

type AZDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.AZ]
	addition[DeleteNoneAddition]
}

type SubDomainDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.SubDomain]
	addition[DeleteNoneAddition]
}

type HostDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Host]
	addition[DeleteNoneAddition]
}

type VMDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VM]
	addition[DeleteNoneAddition]
}

type VMPodNodeConnectionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VMPodNodeConnection]
	addition[DeleteNoneAddition]
}

type VPCDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VPC]
	addition[DeleteNoneAddition]
}

type NetworkDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Network]
	addition[DeleteNoneAddition]
}

type SubnetDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Subnet]
	addition[DeleteNoneAddition]
}

type VRouterDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VRouter]
	addition[DeleteNoneAddition]
}

type RoutingTableDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.RoutingTable]
	addition[DeleteNoneAddition]
}

type DHCPPortDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.DHCPPort]
	addition[DeleteNoneAddition]
}

type VInterfaceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VInterface]
	addition[DeleteNoneAddition]
}

type FloatingIPDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.FloatingIP]
	addition[DeleteNoneAddition]
}

type LANIPDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.LANIP]
	addition[DeleteNoneAddition]
}

type WANIPDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.WANIP]
	addition[DeleteNoneAddition]
}

type VIPDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.VIP]
	addition[DeleteNoneAddition]
}

type NATGatewayDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.NATGateway]
	addition[DeleteNoneAddition]
}

type NATRuleDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.NATRule]
	addition[DeleteNoneAddition]
}

type NATVMConnectionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.NATVMConnection]
	addition[DeleteNoneAddition]
}

type LBDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.LB]
	addition[DeleteNoneAddition]
}

type LBListenerDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.LBListener]
	addition[DeleteNoneAddition]
}

type LBTargetServerDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.LBTargetServer]
	addition[DeleteNoneAddition]
}

type LBVMConnectionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.LBVMConnection]
	addition[DeleteNoneAddition]
}

type PeerConnectionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PeerConnection]
	addition[DeleteNoneAddition]
}

type CENDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.CEN]
	addition[DeleteNoneAddition]
}

type RDSInstanceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type RedisInstanceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.RedisInstance]
	addition[DeleteNoneAddition]
}

type PodClusterDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodCluster]
	addition[DeleteNoneAddition]
}

type PodNamespaceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodNamespace]
	addition[DeleteNoneAddition]
}

type PodNodeDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodNode]
	addition[DeleteNoneAddition]
}

type PodIngressDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngress]
	addition[DeleteNoneAddition]
}

type PodIngressRuleDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngressRule]
	addition[DeleteNoneAddition]
}

type PodIngressRuleBackendDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodIngressRuleBackend]
	addition[DeleteNoneAddition]
}

type PodServiceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodService]
	addition[DeleteNoneAddition]
}

type PodServicePortDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodServicePort]
	addition[DeleteNoneAddition]
}

type PodGroupDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type ConfigMapDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.ConfigMap]
	addition[DeleteNoneAddition]
}

type PodGroupConfigMapConnectionDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroupConfigMapConnection]
	addition[DeleteNoneAddition]
}

type PodGroupPortDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type PodReplicaSetDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.PodReplicaSet]
	addition[DeleteNoneAddition]
}

type PodDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Pod]
	addition[DeleteNoneAddition]
}

type ProcessDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.Process]
	addition[ProcessDeleteAddition]
}

type ProcessDeleteAddition struct {
	DeletedGIDs []uint32
}

type CustomServiceDelete struct {
	Lcuuids
	MetadbItems[metadbmodel.CustomService]
	addition[DeleteNoneAddition]
}
