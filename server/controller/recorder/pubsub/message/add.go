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

import "github.com/deepflowio/deepflow/server/controller/db/mysql"

type RegionAdd struct {
	MySQLItems[mysql.Region]
}

type AZAdd struct {
	MySQLItems[mysql.AZ]
}

type SubDomainAdd struct {
	MySQLItems[mysql.SubDomain]
}

type HostAdd struct {
	MySQLItems[mysql.Host]
}

type VMAdd struct {
	MySQLItems[mysql.VM]
}

type VMPodNodeConnectionAdd struct {
	MySQLItems[mysql.VMPodNodeConnection]
}

type VPCAdd struct {
	MySQLItems[mysql.VPC]
}

type NetworkAdd struct {
	MySQLItems[mysql.Network]
}

type SubnetAdd struct {
	MySQLItems[mysql.Subnet]
}

type VRouterAdd struct {
	MySQLItems[mysql.VRouter]
}

type RoutingTableAdd struct {
	MySQLItems[mysql.RoutingTable]
}

type DHCPPortAdd struct {
	MySQLItems[mysql.DHCPPort]
}

type VInterfaceAdd struct {
	MySQLItems[mysql.VInterface]
}

type FloatingIPAdd struct {
	MySQLItems[mysql.FloatingIP]
}

type LANIPAdd struct {
	MySQLItems[mysql.LANIP]
}

type WANIPAdd struct {
	MySQLItems[mysql.WANIP]
}

type VIPAdd struct {
	MySQLItems[mysql.VIP]
}

type SecurityGroupAdd struct {
	MySQLItems[mysql.SecurityGroup]
}

type SecurityGroupRuleAdd struct {
	MySQLItems[mysql.SecurityGroupRule]
}

type VMSecurityGroupAdd struct {
	MySQLItems[mysql.VMSecurityGroup]
}

type NATGatewayAdd struct {
	MySQLItems[mysql.NATGateway]
}

type NATRuleAdd struct {
	MySQLItems[mysql.NATRule]
}

type NATVMConnectionAdd struct {
	MySQLItems[mysql.NATVMConnection]
}

type LBAdd struct {
	MySQLItems[mysql.LB]
}

type LBListenerAdd struct {
	MySQLItems[mysql.LBListener]
}

type LBTargetServerAdd struct {
	MySQLItems[mysql.LBTargetServer]
}

type LBVMConnectionAdd struct {
	MySQLItems[mysql.LBVMConnection]
}

type PeerConnectionAdd struct {
	MySQLItems[mysql.PeerConnection]
}

type CENAdd struct {
	MySQLItems[mysql.CEN]
}

type RDSInstanceAdd struct {
	MySQLItems[mysql.RDSInstance]
}

type RedisInstanceAdd struct {
	MySQLItems[mysql.RedisInstance]
}

type PodClusterAdd struct {
	MySQLItems[mysql.PodCluster]
}

type PodNamespaceAdd struct {
	MySQLItems[mysql.PodNamespace]
}

type PodNodeAdd struct {
	MySQLItems[mysql.PodNode]
}

type PodIngressAdd struct {
	MySQLItems[mysql.PodIngress]
}

type PodIngressRuleAdd struct {
	MySQLItems[mysql.PodIngressRule]
}

type PodIngressRuleBackendAdd struct {
	MySQLItems[mysql.PodIngressRuleBackend]
}

type PodServiceAdd struct {
	MySQLItems[mysql.PodService]
}

type PodServicePortAdd struct {
	MySQLItems[mysql.PodServicePort]
}

type PodGroupAdd struct {
	MySQLItems[mysql.PodGroup]
}

type PodGroupPortAdd struct {
	MySQLItems[mysql.PodGroupPort]
}

type PodReplicaSetAdd struct {
	MySQLItems[mysql.PodReplicaSet]
}

type PodAdd struct {
	MySQLItems[mysql.Pod]
}

type ProcessAdd struct {
	MySQLItems[mysql.Process]
}

type PrometheusTargetAdd struct {
	MySQLItems[mysql.PrometheusTarget]
}
