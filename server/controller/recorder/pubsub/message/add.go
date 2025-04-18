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
	addition[AddNoneAddition]
}

type AZAdd struct {
	MySQLItems[mysqlmodel.AZ]
	addition[AddNoneAddition]
}

type SubDomainAdd struct {
	MySQLItems[mysqlmodel.SubDomain]
	addition[AddNoneAddition]
}

type HostAdd struct {
	MySQLItems[mysqlmodel.Host]
	addition[AddNoneAddition]
}

type VMAdd struct {
	MySQLItems[mysqlmodel.VM]
	addition[AddNoneAddition]
}

type VMPodNodeConnectionAdd struct {
	MySQLItems[mysqlmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type VPCAdd struct {
	MySQLItems[mysqlmodel.VPC]
	addition[AddNoneAddition]
}

type NetworkAdd struct {
	MySQLItems[mysqlmodel.Network]
	addition[AddNoneAddition]
}

type SubnetAdd struct {
	MySQLItems[mysqlmodel.Subnet]
	addition[AddNoneAddition]
}

type VRouterAdd struct {
	MySQLItems[mysqlmodel.VRouter]
	addition[AddNoneAddition]
}

type RoutingTableAdd struct {
	MySQLItems[mysqlmodel.RoutingTable]
	addition[AddNoneAddition]
}

type DHCPPortAdd struct {
	MySQLItems[mysqlmodel.DHCPPort]
	addition[AddNoneAddition]
}

type VInterfaceAdd struct {
	MySQLItems[mysqlmodel.VInterface]
	addition[AddNoneAddition]
}

type FloatingIPAdd struct {
	MySQLItems[mysqlmodel.FloatingIP]
	addition[AddNoneAddition]
}

type LANIPAdd struct {
	MySQLItems[mysqlmodel.LANIP]
	addition[AddNoneAddition]
}

type WANIPAdd struct {
	MySQLItems[mysqlmodel.WANIP]
	addition[AddNoneAddition]
}

type VIPAdd struct {
	MySQLItems[mysqlmodel.VIP]
	addition[AddNoneAddition]
}

type NATGatewayAdd struct {
	MySQLItems[mysqlmodel.NATGateway]
	addition[AddNoneAddition]
}

type NATRuleAdd struct {
	MySQLItems[mysqlmodel.NATRule]
	addition[AddNoneAddition]
}

type NATVMConnectionAdd struct {
	MySQLItems[mysqlmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type LBAdd struct {
	MySQLItems[mysqlmodel.LB]
	addition[AddNoneAddition]
}

type LBListenerAdd struct {
	MySQLItems[mysqlmodel.LBListener]
	addition[AddNoneAddition]
}

type LBTargetServerAdd struct {
	MySQLItems[mysqlmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type LBVMConnectionAdd struct {
	MySQLItems[mysqlmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type PeerConnectionAdd struct {
	MySQLItems[mysqlmodel.PeerConnection]
	addition[AddNoneAddition]
}

type CENAdd struct {
	MySQLItems[mysqlmodel.CEN]
	addition[AddNoneAddition]
}

type RDSInstanceAdd struct {
	MySQLItems[mysqlmodel.RDSInstance]
	addition[AddNoneAddition]
}

type RedisInstanceAdd struct {
	MySQLItems[mysqlmodel.RedisInstance]
	addition[AddNoneAddition]
}

type PodClusterAdd struct {
	MySQLItems[mysqlmodel.PodCluster]
	addition[AddNoneAddition]
}

type PodNamespaceAdd struct {
	MySQLItems[mysqlmodel.PodNamespace]
	addition[AddNoneAddition]
}

type PodNodeAdd struct {
	MySQLItems[mysqlmodel.PodNode]
	addition[AddNoneAddition]
}

type PodIngressAdd struct {
	MySQLItems[mysqlmodel.PodIngress]
	addition[AddNoneAddition]
}

type PodIngressRuleAdd struct {
	MySQLItems[mysqlmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type PodIngressRuleBackendAdd struct {
	MySQLItems[mysqlmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type PodServiceAdd struct {
	MySQLItems[mysqlmodel.PodService]
	addition[AddNoneAddition]
}

type PodServicePortAdd struct {
	MySQLItems[mysqlmodel.PodServicePort]
	addition[AddNoneAddition]
}

type PodGroupAdd struct {
	MySQLItems[mysqlmodel.PodGroup]
	addition[AddNoneAddition]
}

type PodGroupPortAdd struct {
	MySQLItems[mysqlmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type PodReplicaSetAdd struct {
	MySQLItems[mysqlmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type PodAdd struct {
	MySQLItems[mysqlmodel.Pod]
	addition[AddNoneAddition]
}

type ProcessAdd struct {
	MySQLItems[mysqlmodel.Process]
	addition[ProcessAddAddition]
}

type ProcessAddAddition struct {
	IDToTagRecorderNewGIDFlag map[int]bool // 标识是否是新建的 pid，遵循 tagrecorder 需求，重复使用新建的 pid，仅随机标记 1 次新建
}

type CustomServiceAdd struct {
	MySQLItems[mysqlmodel.CustomService]
	addition[AddNoneAddition]
}
