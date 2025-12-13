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

package tool

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

// Tool consolidates resource data using unified info structs
type Tool struct {
	LogController
	metadata *rcommon.Metadata

	sequence int

	// Clouds
	region *RegionCollection
	az     *AZCollection

	// Computes
	host *HostCollection
	vm   *VMCollection

	// Networks
	vpc        *VPCCollection
	network    *NetworkCollection
	subnet     *SubnetCollection
	vRouter    *VRouterCollection
	dhcpPort   *DHCPPortCollection
	vInterface *VInterfaceCollection
	lanIP      *LANIPCollection
	wanIP      *WANIPCollection

	// Network services
	natGateway *NATGatewayCollection
	lb         *LBCollection
	lbListener *LBListenerCollection

	// Storage services
	rdsInstance   *RDSInstanceCollection
	redisInstance *RedisInstanceCollection

	// Kubernetes
	podCluster                  *PodClusterCollection
	podNode                     *PodNodeCollection
	podNamespace                *PodNamespaceCollection
	podIngress                  *PodIngressCollection
	podIngressRule              *PodIngressRuleCollection
	podService                  *PodServiceCollection
	podGroup                    *PodGroupCollection
	podReplicaSet               *PodReplicaSetCollection
	pod                         *PodCollection
	configMap                   *ConfigMapCollection
	podGroupConfigMapConnection *PodGroupConfigMapConnectionCollection
	vmPodNodeConnection         *VMPodNodeConnectionCollection

	// Processes
	process *ProcessCollection
	agent   *VTapCollection
}

func NewTool(md *rcommon.Metadata) *Tool {
	t := &Tool{
		metadata: md,
	}

	// Clouds
	t.region = NewRegionCollection(t)
	t.az = NewAZCollection(t)

	// Computes
	t.host = NewHostCollection(t)
	t.vm = NewVMCollection(t)

	// Networks
	t.vpc = NewVPCCollection(t)
	t.network = NewNetworkCollection(t)
	t.subnet = NewSubnetCollection(t)
	t.vRouter = NewVRouterCollection(t)
	t.dhcpPort = NewDHCPPortCollection(t)
	t.vInterface = NewVInterfaceCollection(t)
	t.lanIP = NewLANIPCollection(t)
	t.wanIP = NewWANIPCollection(t)

	// Network services
	t.natGateway = NewNATGatewayCollection(t)
	t.lb = NewLBCollection(t)
	t.lbListener = NewLBListenerCollection(t)

	// Storage services
	t.rdsInstance = NewRDSInstanceCollection(t)
	t.redisInstance = NewRedisInstanceCollection(t)

	// Kubernetes
	t.podCluster = NewPodClusterCollection(t)
	t.podNode = NewPodNodeCollection(t)
	t.podNamespace = NewPodNamespaceCollection(t)
	t.podIngress = NewPodIngressCollection(t)
	t.podIngressRule = NewPodIngressRuleCollection(t)
	t.podService = NewPodServiceCollection(t)
	t.podGroup = NewPodGroupCollection(t)
	t.podReplicaSet = NewPodReplicaSetCollection(t)
	t.pod = NewPodCollection(t)
	t.configMap = NewConfigMapCollection(t)
	t.podGroupConfigMapConnection = NewPodGroupConfigMapConnectionCollection(t)

	// Processes
	t.vmPodNodeConnection = NewVMPodNodeConnectionCollection(t)
	t.process = NewProcessCollection(t)
	t.agent = NewVTapCollection(t)

	return t
}

func (t Tool) Metadata() *rcommon.Metadata { return t.metadata }
func (t Tool) Sequence() int               { return t.sequence }
func (t *Tool) SetSequence(sequence int) {
	t.sequence = sequence
}

// Clouds
func (t Tool) Region() *RegionCollection { return t.region }
func (t Tool) AZ() *AZCollection         { return t.az }

// Computes
func (t Tool) Host() *HostCollection             { return t.host }
func (t Tool) VM() *VMCollection                 { return t.vm } // Networks
func (t Tool) VPC() *VPCCollection               { return t.vpc }
func (t Tool) Network() *NetworkCollection       { return t.network }
func (t Tool) Subnet() *SubnetCollection         { return t.subnet }
func (t Tool) VRouter() *VRouterCollection       { return t.vRouter }
func (t Tool) DHCPPort() *DHCPPortCollection     { return t.dhcpPort }
func (t Tool) VInterface() *VInterfaceCollection { return t.vInterface }
func (t Tool) LANIP() *LANIPCollection           { return t.lanIP }
func (t Tool) WANIP() *WANIPCollection           { return t.wanIP }

// Network services
func (t Tool) NATGateway() *NATGatewayCollection { return t.natGateway }
func (t Tool) LB() *LBCollection                 { return t.lb }
func (t Tool) LBListener() *LBListenerCollection { return t.lbListener }

// Storage services
func (t Tool) RDSInstance() *RDSInstanceCollection     { return t.rdsInstance }
func (t Tool) RedisInstance() *RedisInstanceCollection { return t.redisInstance }

// Kubernetes
func (t Tool) PodCluster() *PodClusterCollection         { return t.podCluster }
func (t Tool) PodNode() *PodNodeCollection               { return t.podNode }
func (t Tool) PodNamespace() *PodNamespaceCollection     { return t.podNamespace }
func (t Tool) PodIngress() *PodIngressCollection         { return t.podIngress }
func (t Tool) PodIngressRule() *PodIngressRuleCollection { return t.podIngressRule }
func (t Tool) PodService() *PodServiceCollection         { return t.podService }
func (t Tool) PodGroup() *PodGroupCollection             { return t.podGroup }
func (t Tool) PodReplicaSet() *PodReplicaSetCollection   { return t.podReplicaSet }
func (t Tool) Pod() *PodCollection                       { return t.pod }
func (t Tool) ConfigMap() *ConfigMapCollection           { return t.configMap }
func (t Tool) PodGroupConfigMapConnection() *PodGroupConfigMapConnectionCollection {
	return t.podGroupConfigMapConnection
}
func (t Tool) VMPodNodeConnection() *VMPodNodeConnectionCollection { return t.vmPodNodeConnection }

// Processes
func (t Tool) Process() *ProcessCollection { return t.process }
func (t Tool) Agent() *VTapCollection      { return t.agent }

func (t Tool) GetDeviceVPCIDByLcuuid(deviceType int, deviceLcuuid string) (int, bool) {
	var vpcID int
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		vpcID = t.VM().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		vpcID = t.VRouter().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		vpcID = t.DHCPPort().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		vpcID = t.NATGateway().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		vpcID = t.LB().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		vpcID = t.RDSInstance().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		vpcID = t.RedisInstance().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		vpcID = t.PodNode().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		vpcID = t.PodService().GetByLcuuid(deviceLcuuid).VPCID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		vpcID = t.Pod().GetByLcuuid(deviceLcuuid).VPCID()
	default:
		log.Errorf("device type %d not supported", deviceType, t.metadata.LogPrefixes)
		return 0, false
	}

	return 0, vpcID != 0
}

func (t Tool) GetDeviceIDByLcuuid(deviceType int, deviceLcuuid string) (int, bool) {
	var id int
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		id = t.VM().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		id = t.VRouter().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		id = t.DHCPPort().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		id = t.NATGateway().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		id = t.LB().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		id = t.RDSInstance().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		id = t.RedisInstance().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		id = t.PodNode().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		id = t.PodService().GetByLcuuid(deviceLcuuid).ID()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		id = t.Pod().GetByLcuuid(deviceLcuuid).ID()
	default:
		log.Errorf("device type %d not supported", deviceType, t.metadata.LogPrefixes)
		return 0, false
	}

	return id, id != 0
}

func (t Tool) GetDeviceLcuuidByID(deviceType int, deviceID int) (string, bool) {
	var lcuuid string
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		lcuuid = t.VM().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		lcuuid = t.VRouter().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		lcuuid = t.DHCPPort().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		lcuuid = t.NATGateway().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		lcuuid = t.LB().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		lcuuid = t.RDSInstance().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		lcuuid = t.RedisInstance().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		lcuuid = t.PodNode().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		lcuuid = t.PodService().GetByID(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		lcuuid = t.Pod().GetByID(deviceID).Lcuuid()
	default:
		log.Errorf("device type %d not supported", deviceType, t.metadata.LogPrefixes)
		return "", false
	}

	return lcuuid, lcuuid != ""
}

func (t Tool) GetProcessDeviceTypeAndID(containterID string, agentID int) (deviceType, deviceID int) {
	pod := t.Pod().GetByContainerID(containterID)
	if pod.IsValid() {
		deviceType = ctrlrcommon.VIF_DEVICE_TYPE_POD
		deviceID = pod.ID()
		return
	}
	agent := t.Agent().GetByID(agentID)
	deviceType = ctrlrcommon.VTAP_TYPE_TO_DEVICE_TYPE[agent.Type()]
	deviceID = agent.LaunchServerID()
	return
}
