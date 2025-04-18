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
	addition[AddNoneAddition]
}

type AZAdd struct {
	MySQLItems[metadbmodel.AZ]
	addition[AddNoneAddition]
}

type SubDomainAdd struct {
	MySQLItems[metadbmodel.SubDomain]
	addition[AddNoneAddition]
}

type HostAdd struct {
	MySQLItems[metadbmodel.Host]
	addition[AddNoneAddition]
}

type VMAdd struct {
	MySQLItems[metadbmodel.VM]
	addition[AddNoneAddition]
}

type VMPodNodeConnectionAdd struct {
	MySQLItems[metadbmodel.VMPodNodeConnection]
	addition[AddNoneAddition]
}

type VPCAdd struct {
	MySQLItems[metadbmodel.VPC]
	addition[AddNoneAddition]
}

type NetworkAdd struct {
	MySQLItems[metadbmodel.Network]
	addition[AddNoneAddition]
}

type SubnetAdd struct {
	MySQLItems[metadbmodel.Subnet]
	addition[AddNoneAddition]
}

type VRouterAdd struct {
	MySQLItems[metadbmodel.VRouter]
	addition[AddNoneAddition]
}

type RoutingTableAdd struct {
	MySQLItems[metadbmodel.RoutingTable]
	addition[AddNoneAddition]
}

type DHCPPortAdd struct {
	MySQLItems[metadbmodel.DHCPPort]
	addition[AddNoneAddition]
}

type VInterfaceAdd struct {
	MySQLItems[metadbmodel.VInterface]
	addition[AddNoneAddition]
}

type FloatingIPAdd struct {
	MySQLItems[metadbmodel.FloatingIP]
	addition[AddNoneAddition]
}

type LANIPAdd struct {
	MySQLItems[metadbmodel.LANIP]
	addition[AddNoneAddition]
}

type WANIPAdd struct {
	MySQLItems[metadbmodel.WANIP]
	addition[AddNoneAddition]
}

type VIPAdd struct {
	MySQLItems[metadbmodel.VIP]
	addition[AddNoneAddition]
}

type NATGatewayAdd struct {
	MySQLItems[metadbmodel.NATGateway]
	addition[AddNoneAddition]
}

type NATRuleAdd struct {
	MySQLItems[metadbmodel.NATRule]
	addition[AddNoneAddition]
}

type NATVMConnectionAdd struct {
	MySQLItems[metadbmodel.NATVMConnection]
	addition[AddNoneAddition]
}

type LBAdd struct {
	MySQLItems[metadbmodel.LB]
	addition[AddNoneAddition]
}

type LBListenerAdd struct {
	MySQLItems[metadbmodel.LBListener]
	addition[AddNoneAddition]
}

type LBTargetServerAdd struct {
	MySQLItems[metadbmodel.LBTargetServer]
	addition[AddNoneAddition]
}

type LBVMConnectionAdd struct {
	MySQLItems[metadbmodel.LBVMConnection]
	addition[AddNoneAddition]
}

type PeerConnectionAdd struct {
	MySQLItems[metadbmodel.PeerConnection]
	addition[AddNoneAddition]
}

type CENAdd struct {
	MySQLItems[metadbmodel.CEN]
	addition[AddNoneAddition]
}

type RDSInstanceAdd struct {
	MySQLItems[metadbmodel.RDSInstance]
	addition[AddNoneAddition]
}

type RedisInstanceAdd struct {
	MySQLItems[metadbmodel.RedisInstance]
	addition[AddNoneAddition]
}

type PodClusterAdd struct {
	MySQLItems[metadbmodel.PodCluster]
	addition[AddNoneAddition]
}

type PodNamespaceAdd struct {
	MySQLItems[metadbmodel.PodNamespace]
	addition[AddNoneAddition]
}

type PodNodeAdd struct {
	MySQLItems[metadbmodel.PodNode]
	addition[AddNoneAddition]
}

type PodIngressAdd struct {
	MySQLItems[metadbmodel.PodIngress]
	addition[AddNoneAddition]
}

type PodIngressRuleAdd struct {
	MySQLItems[metadbmodel.PodIngressRule]
	addition[AddNoneAddition]
}

type PodIngressRuleBackendAdd struct {
	MySQLItems[metadbmodel.PodIngressRuleBackend]
	addition[AddNoneAddition]
}

type PodServiceAdd struct {
	MySQLItems[metadbmodel.PodService]
	addition[AddNoneAddition]
}

type PodServicePortAdd struct {
	MySQLItems[metadbmodel.PodServicePort]
	addition[AddNoneAddition]
}

type PodGroupAdd struct {
	MySQLItems[metadbmodel.PodGroup]
	addition[AddNoneAddition]
}

type PodGroupPortAdd struct {
	MySQLItems[metadbmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type PodReplicaSetAdd struct {
	MySQLItems[metadbmodel.PodReplicaSet]
	addition[AddNoneAddition]
}

type PodAdd struct {
	MySQLItems[metadbmodel.Pod]
	addition[AddNoneAddition]
}

type ProcessAdd struct {
	MySQLItems[metadbmodel.Process]
	addition[ProcessAddAddition]
}

type ProcessAddAddition struct {
	IDToTagRecorderNewGIDFlag map[int]bool // 标识是否是新建的 pid，遵循 tagrecorder 需求，重复使用新建的 pid，仅随机标记 1 次新建
}

type CustomServiceAdd struct {
	MySQLItems[metadbmodel.CustomService]
	addition[AddNoneAddition]
}
