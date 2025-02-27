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
)

type RegionAdd struct {
	MySQLItems[mysqlmodel.Region]
}

type AZAdd struct {
	MySQLItems[mysqlmodel.AZ]
}

type SubDomainAdd struct {
	MySQLItems[mysqlmodel.SubDomain]
}

type HostAdd struct {
	MySQLItems[mysqlmodel.Host]
}

type VMAdd struct {
	MySQLItems[mysqlmodel.VM]
}

type VMPodNodeConnectionAdd struct {
	MySQLItems[mysqlmodel.VMPodNodeConnection]
}

type VPCAdd struct {
	MySQLItems[mysqlmodel.VPC]
}

type NetworkAdd struct {
	MySQLItems[mysqlmodel.Network]
}

type SubnetAdd struct {
	MySQLItems[mysqlmodel.Subnet]
}

type VRouterAdd struct {
	MySQLItems[mysqlmodel.VRouter]
}

type RoutingTableAdd struct {
	MySQLItems[mysqlmodel.RoutingTable]
}

type DHCPPortAdd struct {
	MySQLItems[mysqlmodel.DHCPPort]
}

type VInterfaceAdd struct {
	MySQLItems[mysqlmodel.VInterface]
}

type FloatingIPAdd struct {
	MySQLItems[mysqlmodel.FloatingIP]
}

type LANIPAdd struct {
	MySQLItems[mysqlmodel.LANIP]
}

type WANIPAdd struct {
	MySQLItems[mysqlmodel.WANIP]
}

type VIPAdd struct {
	MySQLItems[mysqlmodel.VIP]
}

type NATGatewayAdd struct {
	MySQLItems[mysqlmodel.NATGateway]
}

type NATRuleAdd struct {
	MySQLItems[mysqlmodel.NATRule]
}

type NATVMConnectionAdd struct {
	MySQLItems[mysqlmodel.NATVMConnection]
}

type LBAdd struct {
	MySQLItems[mysqlmodel.LB]
}

type LBListenerAdd struct {
	MySQLItems[mysqlmodel.LBListener]
}

type LBTargetServerAdd struct {
	MySQLItems[mysqlmodel.LBTargetServer]
}

type LBVMConnectionAdd struct {
	MySQLItems[mysqlmodel.LBVMConnection]
}

type PeerConnectionAdd struct {
	MySQLItems[mysqlmodel.PeerConnection]
}

type CENAdd struct {
	MySQLItems[mysqlmodel.CEN]
}

type RDSInstanceAdd struct {
	MySQLItems[mysqlmodel.RDSInstance]
}

type RedisInstanceAdd struct {
	MySQLItems[mysqlmodel.RedisInstance]
}

type PodClusterAdd struct {
	MySQLItems[mysqlmodel.PodCluster]
}

type PodNamespaceAdd struct {
	MySQLItems[mysqlmodel.PodNamespace]
}

type PodNodeAdd struct {
	MySQLItems[mysqlmodel.PodNode]
}

type PodIngressAdd struct {
	MySQLItems[mysqlmodel.PodIngress]
}

type PodIngressRuleAdd struct {
	MySQLItems[mysqlmodel.PodIngressRule]
}

type PodIngressRuleBackendAdd struct {
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
}

type PodServiceAdd struct {
	MySQLItems[mysqlmodel.PodService]
}

type PodServicePortAdd struct {
	MySQLItems[mysqlmodel.PodServicePort]
}

type PodGroupAdd struct {
	MySQLItems[mysqlmodel.PodGroup]
}

type PodGroupPortAdd struct {
	MySQLItems[mysqlmodel.PodGroupPort]
}

type PodReplicaSetAdd struct {
	MySQLItems[mysqlmodel.PodReplicaSet]
}

type PodAdd struct {
	MySQLItems[mysqlmodel.Pod]
}

type ProcessAdd struct {
	MySQLItems[mysqlmodel.Process]
}

type CustomServiceAdd struct {
	MySQLItems[mysqlmodel.CustomService]
}
