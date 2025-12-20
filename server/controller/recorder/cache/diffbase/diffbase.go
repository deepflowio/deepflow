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
	d.az = NewAZCollection(t)

	// Computes
	d.host = NewHostCollection(t)
	d.vm = NewVMCollection(t)

	// Networks
	d.vpc = NewVPCCollection(t)
	d.network = NewNetworkCollection(t)
	d.subnet = NewSubnetCollection(t)
	d.vRouter = NewVRouterCollection(t)
	d.routingTable = NewRoutingTableCollection(t)
	d.dhcpPort = NewDHCPPortCollection(t)
	d.vInterface = NewVInterfaceCollection(t)
	d.lanIP = NewLANIPCollection(t)
	d.wanIP = NewWANIPCollection(t)
	d.floatingIP = NewFloatingIPCollection(t)
	d.vip = NewVIPCollection(t)

	// Network services
	d.natGateway = NewNATGatewayCollection(t)
	d.natRule = NewNATRuleCollection(t)
	d.natVMConnection = NewNATVMConnectionCollection(t)
	d.lb = NewLBCollection(t)
	d.lbListener = NewLBListenerCollection(t)
	d.lbTargetServer = NewLBTargetServerCollection(t)
	d.lbVMConnection = NewLBVMConnectionCollection(t)
	d.cen = NewCENCollection(t)
	d.peerConnection = NewPeerConnectionCollection(t)

	// Storage services
	d.rdsInstance = NewRDSInstanceCollection(t)
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
	d.vmPodNodeConnection = NewVMPodNodeConnectionCollection(t)
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
	az        *AZCollection

	// Computes
	host *HostCollection
	vm   *VMCollection

	// Networks
	vpc          *VPCCollection
	network      *NetworkCollection
	subnet       *SubnetCollection
	vRouter      *VRouterCollection
	routingTable *RoutingTableCollection
	dhcpPort     *DHCPPortCollection
	vInterface   *VInterfaceCollection
	lanIP        *LANIPCollection
	wanIP        *WANIPCollection
	floatingIP   *FloatingIPCollection
	vip          *VIPCollection

	// Network services
	natGateway      *NATGatewayCollection
	natRule         *NATRuleCollection
	natVMConnection *NATVMConnectionCollection
	lb              *LBCollection
	lbListener      *LBListenerCollection
	lbTargetServer  *LBTargetServerCollection
	lbVMConnection  *LBVMConnectionCollection
	cen             *CENCollection
	peerConnection  *PeerConnectionCollection

	// Storage services
	rdsInstance   *RDSInstanceCollection
	redisInstance *RedisInstanceCollection

	// Kubernetes
	podCluster                  *PodClusterCollection
	podNode                     *PodNodeCollection
	vmPodNodeConnection         *VMPodNodeConnectionCollection
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
func (d DiffBases) AZ() *AZCollection               { return d.az }

// Computes
func (d DiffBases) Host() *HostCollection { return d.host }
func (d DiffBases) VM() *VMCollection     { return d.vm }

// Networks
func (d DiffBases) VPC() *VPCCollection                   { return d.vpc }
func (d DiffBases) Network() *NetworkCollection           { return d.network }
func (d DiffBases) Subnet() *SubnetCollection             { return d.subnet }
func (d DiffBases) VRouter() *VRouterCollection           { return d.vRouter }
func (d DiffBases) RoutingTable() *RoutingTableCollection { return d.routingTable }
func (d DiffBases) DHCPPort() *DHCPPortCollection         { return d.dhcpPort }
func (d DiffBases) VInterface() *VInterfaceCollection     { return d.vInterface }
func (d DiffBases) LANIP() *LANIPCollection               { return d.lanIP }
func (d DiffBases) WANIP() *WANIPCollection               { return d.wanIP }
func (d DiffBases) FloatingIP() *FloatingIPCollection     { return d.floatingIP }
func (d DiffBases) VIP() *VIPCollection                   { return d.vip }

// Network services
func (d DiffBases) NATGateway() *NATGatewayCollection           { return d.natGateway }
func (d DiffBases) NATRule() *NATRuleCollection                 { return d.natRule }
func (d DiffBases) NATVMConnection() *NATVMConnectionCollection { return d.natVMConnection }
func (d DiffBases) LB() *LBCollection                           { return d.lb }
func (d DiffBases) LBListener() *LBListenerCollection           { return d.lbListener }
func (d DiffBases) LBTargetServer() *LBTargetServerCollection   { return d.lbTargetServer }
func (d DiffBases) LBVMConnection() *LBVMConnectionCollection   { return d.lbVMConnection }
func (d DiffBases) CEN() *CENCollection                         { return d.cen }
func (d DiffBases) PeerConnection() *PeerConnectionCollection   { return d.peerConnection }

// Storage services
func (d DiffBases) RDSInstance() *RDSInstanceCollection     { return d.rdsInstance }
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
func (d DiffBases) VMPodNodeConnection() *VMPodNodeConnectionCollection {
	return d.vmPodNodeConnection
}
func (d DiffBases) PodGroupConfigMapConnection() *PodGroupConfigMapConnectionCollection {
	return d.podGroupConfigMapConnection
}

// Processes
func (d DiffBases) Process() *ProcessCollection { return d.process }
