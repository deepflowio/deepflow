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

type RegionAdd struct {
	MetadbItems[metadbmodel.Region]
	addition[AddNoneAddition]
}

type AZAdd struct {
	MetadbItems[metadbmodel.AZ]
	addition[AddNoneAddition]
}

type SubDomainAdd struct {
	MetadbItems[metadbmodel.SubDomain]
	addition[AddNoneAddition]
}

type HostAdd struct {
	MetadbItems[metadbmodel.Host]
	addition[AddNoneAddition]
}

type VMAdd struct {
	MetadbItems[metadbmodel.VM]
	addition[AddNoneAddition]
}

type VMPodNodeConnectionAdd struct {
	MetadbItems[metadbmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type VPCAdd struct {
	MetadbItems[metadbmodel.VPC]
	addition[AddNoneAddition]
}

type NetworkAdd struct {
	MetadbItems[metadbmodel.Network]
	addition[AddNoneAddition]
}

type SubnetAdd struct {
	MetadbItems[metadbmodel.Subnet]
	addition[AddNoneAddition]
}

type VRouterAdd struct {
	MetadbItems[metadbmodel.VRouter]
	addition[AddNoneAddition]
}

type RoutingTableAdd struct {
	MetadbItems[metadbmodel.RoutingTable]
	addition[AddNoneAddition]
}

type DHCPPortAdd struct {
	MetadbItems[metadbmodel.DHCPPort]
	addition[AddNoneAddition]
}

type VInterfaceAdd struct {
	MetadbItems[metadbmodel.VInterface]
	addition[AddNoneAddition]
}

type FloatingIPAdd struct {
	MetadbItems[metadbmodel.FloatingIP]
	addition[AddNoneAddition]
}

type LANIPAdd struct {
	MetadbItems[metadbmodel.LANIP]
	addition[AddNoneAddition]
}

type WANIPAdd struct {
	MetadbItems[metadbmodel.WANIP]
	addition[AddNoneAddition]
}

type VIPAdd struct {
	MetadbItems[metadbmodel.VIP]
	addition[AddNoneAddition]
}

type NATGatewayAdd struct {
	MetadbItems[metadbmodel.NATGateway]
	addition[AddNoneAddition]
}

type NATRuleAdd struct {
	MetadbItems[metadbmodel.NATRule]
	addition[AddNoneAddition]
}

type NATVMConnectionAdd struct {
	MetadbItems[metadbmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type LBAdd struct {
	MetadbItems[metadbmodel.LB]
	addition[AddNoneAddition]
}

type LBListenerAdd struct {
	MetadbItems[metadbmodel.LBListener]
	addition[AddNoneAddition]
}

type LBTargetServerAdd struct {
	MetadbItems[metadbmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type LBVMConnectionAdd struct {
	MetadbItems[metadbmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type PeerConnectionAdd struct {
	MetadbItems[metadbmodel.PeerConnection]
	addition[AddNoneAddition]
}

type CENAdd struct {
	MetadbItems[metadbmodel.CEN]
	addition[AddNoneAddition]
}

type RDSInstanceAdd struct {
	MetadbItems[metadbmodel.RDSInstance]
	addition[AddNoneAddition]
}

type RedisInstanceAdd struct {
	MetadbItems[metadbmodel.RedisInstance]
	addition[AddNoneAddition]
}

type PodClusterAdd struct {
	MetadbItems[metadbmodel.PodCluster]
	addition[AddNoneAddition]
}

type PodNamespaceAdd struct {
	MetadbItems[metadbmodel.PodNamespace]
	addition[AddNoneAddition]
}

type PodNodeAdd struct {
	MetadbItems[metadbmodel.PodNode]
	addition[AddNoneAddition]
}

type PodIngressAdd struct {
	MetadbItems[metadbmodel.PodIngress]
	addition[AddNoneAddition]
}

type PodIngressRuleAdd struct {
	MetadbItems[metadbmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type PodIngressRuleBackendAdd struct {
	MetadbItems[metadbmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type PodServiceAdd struct {
	MetadbItems[metadbmodel.PodService]
	addition[AddNoneAddition]
}

type PodServicePortAdd struct {
	MetadbItems[metadbmodel.PodServicePort]
	addition[AddNoneAddition]
}

type PodGroupAdd struct {
	MetadbItems[metadbmodel.PodGroup]
	addition[AddNoneAddition]
}

type ConfigMapAdd struct {
	MetadbItems[metadbmodel.ConfigMap]
	addition[AddNoneAddition]
}

type PodGroupConfigMapConnectionAdd struct {
	MetadbItems[metadbmodel.PodGroupConfigMapConnection]
	addition[AddNoneAddition]
}

type PodGroupPortAdd struct {
	MetadbItems[metadbmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type PodReplicaSetAdd struct {
	MetadbItems[metadbmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type PodAdd struct {
	MetadbItems[metadbmodel.Pod]
	addition[AddNoneAddition]
}

type ProcessAdd struct {
	MetadbItems[metadbmodel.Process]
	addition[ProcessAddAddition]
}

type ProcessAddAddition struct {
	// CreatedGIDs []uint32 // reserved for tagrecorder use
}

type CustomServiceAdd struct {
	MetadbItems[metadbmodel.CustomService]
	addition[AddNoneAddition]
}
