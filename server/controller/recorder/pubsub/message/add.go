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
	MySQLItems[metadbmodel.Region]
}

type AZAdd struct {
	MySQLItems[metadbmodel.AZ]
}

type SubDomainAdd struct {
	MySQLItems[metadbmodel.SubDomain]
}

type HostAdd struct {
	MySQLItems[metadbmodel.Host]
}

type VMAdd struct {
	MySQLItems[metadbmodel.VM]
}

type VMPodNodeConnectionAdd struct {
	MySQLItems[metadbmodel.VMPodNodeConnection]
}

type VPCAdd struct {
	MySQLItems[metadbmodel.VPC]
}

type NetworkAdd struct {
	MySQLItems[metadbmodel.Network]
}

type SubnetAdd struct {
	MySQLItems[metadbmodel.Subnet]
}

type VRouterAdd struct {
	MySQLItems[metadbmodel.VRouter]
}

type RoutingTableAdd struct {
	MySQLItems[metadbmodel.RoutingTable]
}

type DHCPPortAdd struct {
	MySQLItems[metadbmodel.DHCPPort]
}

type VInterfaceAdd struct {
	MySQLItems[metadbmodel.VInterface]
}

type FloatingIPAdd struct {
	MySQLItems[metadbmodel.FloatingIP]
}

type LANIPAdd struct {
	MySQLItems[metadbmodel.LANIP]
}

type WANIPAdd struct {
	MySQLItems[metadbmodel.WANIP]
}

type VIPAdd struct {
	MySQLItems[metadbmodel.VIP]
}

type NATGatewayAdd struct {
	MySQLItems[metadbmodel.NATGateway]
}

type NATRuleAdd struct {
	MySQLItems[metadbmodel.NATRule]
}

type NATVMConnectionAdd struct {
	MySQLItems[metadbmodel.NATVMConnection]
}

type LBAdd struct {
	MySQLItems[metadbmodel.LB]
}

type LBListenerAdd struct {
	MySQLItems[metadbmodel.LBListener]
}

type LBTargetServerAdd struct {
	MySQLItems[metadbmodel.LBTargetServer]
}

type LBVMConnectionAdd struct {
	MySQLItems[metadbmodel.LBVMConnection]
}

type PeerConnectionAdd struct {
	MySQLItems[metadbmodel.PeerConnection]
}

type CENAdd struct {
	MySQLItems[metadbmodel.CEN]
}

type RDSInstanceAdd struct {
	MySQLItems[metadbmodel.RDSInstance]
}

type RedisInstanceAdd struct {
	MySQLItems[metadbmodel.RedisInstance]
}

type PodClusterAdd struct {
	MySQLItems[metadbmodel.PodCluster]
}

type PodNamespaceAdd struct {
	MySQLItems[metadbmodel.PodNamespace]
}

type PodNodeAdd struct {
	MySQLItems[metadbmodel.PodNode]
}

type PodIngressAdd struct {
	MySQLItems[metadbmodel.PodIngress]
}

type PodIngressRuleAdd struct {
	MySQLItems[metadbmodel.PodIngressRule]
}

type PodIngressRuleBackendAdd struct {
	MySQLItems[metadbmodel.PodIngressRuleBackend]
}

type PodServiceAdd struct {
	MySQLItems[metadbmodel.PodService]
}

type PodServicePortAdd struct {
	MySQLItems[metadbmodel.PodServicePort]
}

type PodGroupAdd struct {
	MySQLItems[metadbmodel.PodGroup]
}

type PodGroupPortAdd struct {
	MySQLItems[metadbmodel.PodGroupPort]
}

type PodReplicaSetAdd struct {
	MySQLItems[metadbmodel.PodReplicaSet]
}

type PodAdd struct {
	MySQLItems[metadbmodel.Pod]
}

type ProcessAdd struct {
	MySQLItems[metadbmodel.Process]
}
