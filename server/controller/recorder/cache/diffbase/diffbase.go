/*
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

package diffbase

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	common "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

// FIXME
// AI key words to add a new struct: analyze this file, add new field podReplicaSet below podGroupPort in struct,
// and add methods or initialization for this field.

func NewDiffBases(t *tool.Tool) *DiffBases {
	d := &DiffBases{}

	// Clouds
	d.subDomain = NewSubDomainCollection(t)
	d.region = NewRegionCollection(t)
	d.az = NewAzCollection(t)

	// Computes
	d.host = NewHostCollection(t)
	d.vm = NewVmCollection(t)

	// Networks
	d.vpc = NewVpcCollection(t)
	d.network = NewNetworkCollection(t)
	d.subnet = NewSubnetCollection(t)
	d.vRouter = NewVrouterCollection(t)
	d.routingTable = NewRoutingTableCollection(t)
	d.dhcpPort = NewDhcpPortCollection(t)
	d.vInterface = NewVinterfaceCollection(t)
	d.lanIP = NewLanIpCollection(t)
	d.wanIP = NewWanIpCollection(t)
	d.floatingIP = NewFloatingIpCollection(t)
	d.vip = NewVipCollection(t)

	// Network services
	d.natGateway = NewNatGatewayCollection(t)
	d.natRule = NewNatRuleCollection(t)
	d.natVMConnection = NewNatVmConnectionCollection(t)
	d.lb = NewLbCollection(t)
	d.lbListener = NewLbListenerCollection(t)
	d.lbTargetServer = NewLbTargetServerCollection(t)
	d.lbVMConnection = NewLbVmConnectionCollection(t)
	d.cen = NewCenCollection(t)
	d.peerConnection = NewPeerConnectionCollection(t)

	// Storage services
	d.rdsInstance = NewRdsInstanceCollection(t)
	d.redisInstance = NewRedisInstanceCollection(t)

	// Kubernetes
	d.podCluster = NewPodClusterCollection(t)
	d.podNode = NewPodNodeCollection(t)
	d.podNamespace = NewPodNamespaceCollection(t)
	d.podIngress = NewPodIngressCollection(t)
	d.podIngressRule = NewPodIngressRuleCollection(t)
	d.podService = NewPodServiceCollection(t)
	d.podGroup = NewPodGroupCollection(t)
	d.pod = NewPodCollection(t)
	d.podGroupPort = NewPodGroupPortCollection(t)
	d.podReplicaSet = NewPodReplicaSetCollection(t)
	d.podServicePort = NewPodServicePortCollection(t)
	d.podIngressRuleBackend = NewPodIngressRuleBackendCollection(t)
	d.vmPodNodeConnection = NewVmPodNodeConnectionCollection(t)
	d.configMap = NewConfigMapCollection(t)
	d.podGroupConfigMapConnection = NewPodGroupConfigMapConnectionCollection(t)

	// Processes
	d.process = NewProcessCollection(t)

	return d
}

type DiffBases struct {
	metadata *common.Metadata
	LogController

	// Clouds
	subDomain *SubDomainCollection
	region    *RegionCollection
	az        *AzCollection

	// Computes
	host *HostCollection
	vm   *VmCollection

	// Networks
	vpc          *VpcCollection
	network      *NetworkCollection
	subnet       *SubnetCollection
	vRouter      *VrouterCollection
	routingTable *RoutingTableCollection
	dhcpPort     *DhcpPortCollection
	vInterface   *VinterfaceCollection
	lanIP        *LanIpCollection
	wanIP        *WanIpCollection
	floatingIP   *FloatingIpCollection
	vip          *VipCollection

	// Network services
	natGateway      *NatGatewayCollection
	natRule         *NatRuleCollection
	natVMConnection *NatVmConnectionCollection
	lb              *LbCollection
	lbListener      *LbListenerCollection
	lbTargetServer  *LbTargetServerCollection
	lbVMConnection  *LbVmConnectionCollection
	cen             *CenCollection
	peerConnection  *PeerConnectionCollection

	// Storage services
	rdsInstance   *RdsInstanceCollection
	redisInstance *RedisInstanceCollection

	// Kubernetes
	podCluster                  *PodClusterCollection
	podNode                     *PodNodeCollection
	vmPodNodeConnection         *VmPodNodeConnectionCollection
	podNamespace                *PodNamespaceCollection
	podIngress                  *PodIngressCollection
	podIngressRule              *PodIngressRuleCollection
	podIngressRuleBackend       *PodIngressRuleBackendCollection
	podService                  *PodServiceCollection
	podServicePort              *PodServicePortCollection
	podGroup                    *PodGroupCollection
	podGroupPort                *PodGroupPortCollection
	podReplicaSet               *PodReplicaSetCollection
	pod                         *PodCollection
	configMap                   *ConfigMapCollection
	podGroupConfigMapConnection *PodGroupConfigMapConnectionCollection

	// Processes
	process *ProcessCollection
}

// Clouds
func (d DiffBases) SubDomain() *SubDomainCollection { return d.subDomain }
func (d DiffBases) Region() *RegionCollection       { return d.region }
func (d DiffBases) AZ() *AzCollection               { return d.az }

// Computes
func (d DiffBases) Host() *HostCollection { return d.host }
func (d DiffBases) VM() *VmCollection     { return d.vm }

// Networks
func (d DiffBases) VPC() *VpcCollection                   { return d.vpc }
func (d DiffBases) Network() *NetworkCollection           { return d.network }
func (d DiffBases) Subnet() *SubnetCollection             { return d.subnet }
func (d DiffBases) VRouter() *VrouterCollection           { return d.vRouter }
func (d DiffBases) RoutingTable() *RoutingTableCollection { return d.routingTable }
func (d DiffBases) DHCPPort() *DhcpPortCollection         { return d.dhcpPort }
func (d DiffBases) VInterface() *VinterfaceCollection     { return d.vInterface }
func (d DiffBases) LANIP() *LanIpCollection               { return d.lanIP }
func (d DiffBases) WANIP() *WanIpCollection               { return d.wanIP }
func (d DiffBases) FloatingIP() *FloatingIpCollection     { return d.floatingIP }
func (d DiffBases) VIP() *VipCollection                   { return d.vip }

// Network services
func (d DiffBases) NATGateway() *NatGatewayCollection           { return d.natGateway }
func (d DiffBases) NATRule() *NatRuleCollection                 { return d.natRule }
func (d DiffBases) NATVMConnection() *NatVmConnectionCollection { return d.natVMConnection }
func (d DiffBases) LB() *LbCollection                           { return d.lb }
func (d DiffBases) LBListener() *LbListenerCollection           { return d.lbListener }
func (d DiffBases) LBTargetServer() *LbTargetServerCollection   { return d.lbTargetServer }
func (d DiffBases) LBVMConnection() *LbVmConnectionCollection   { return d.lbVMConnection }
func (d DiffBases) CEN() *CenCollection                         { return d.cen }
func (d DiffBases) PeerConnection() *PeerConnectionCollection   { return d.peerConnection }

// Storage services
func (d DiffBases) RDSInstance() *RdsInstanceCollection     { return d.rdsInstance }
func (d DiffBases) RedisInstance() *RedisInstanceCollection { return d.redisInstance }

// Kubernetes
func (d DiffBases) PodCluster() *PodClusterCollection         { return d.podCluster }
func (d DiffBases) PodNode() *PodNodeCollection               { return d.podNode }
func (d DiffBases) PodNamespace() *PodNamespaceCollection     { return d.podNamespace }
func (d DiffBases) PodIngress() *PodIngressCollection         { return d.podIngress }
func (d DiffBases) PodIngressRule() *PodIngressRuleCollection { return d.podIngressRule }
func (d DiffBases) PodService() *PodServiceCollection         { return d.podService }
func (d DiffBases) PodGroup() *PodGroupCollection             { return d.podGroup }
func (d DiffBases) Pod() *PodCollection                       { return d.pod }
func (d DiffBases) PodGroupPort() *PodGroupPortCollection     { return d.podGroupPort }
func (d DiffBases) PodReplicaSet() *PodReplicaSetCollection   { return d.podReplicaSet }
func (d DiffBases) PodServicePort() *PodServicePortCollection { return d.podServicePort }
func (d DiffBases) ConfigMap() *ConfigMapCollection           { return d.configMap }
func (d DiffBases) PodIngressRuleBackend() *PodIngressRuleBackendCollection {
	return d.podIngressRuleBackend
}
func (d DiffBases) VMPodNodeConnection() *VmPodNodeConnectionCollection {
	return d.vmPodNodeConnection
}
func (d DiffBases) PodGroupConfigMapConnection() *PodGroupConfigMapConnectionCollection {
	return d.podGroupConfigMapConnection
}

// Processes
func (d DiffBases) Process() *ProcessCollection { return d.process }
