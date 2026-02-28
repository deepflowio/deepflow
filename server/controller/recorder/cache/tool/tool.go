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
	az     *AzCollection

	// Computes
	host *HostCollection
	vm   *VmCollection

	// Networks
	vpc        *VpcCollection
	network    *NetworkCollection
	subnet     *SubnetCollection
	vrouter    *VrouterCollection
	dhcpPort   *DhcpPortCollection
	vinterface *VinterfaceCollection
	lanIP      *LanIpCollection
	wanIP      *WanIpCollection

	// Network services
	natGateway *NatGatewayCollection
	lb         *LbCollection
	lbListener *LbListenerCollection

	// Storage services
	rdsInstance   *RdsInstanceCollection
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
	vmPodNodeConnection         *VmPodNodeConnectionCollection

	// Processes
	process *ProcessCollection
	agent   *VtapCollection
}

func NewTool(md *rcommon.Metadata) *Tool {
	t := &Tool{
		metadata: md,
	}

	// Clouds
	t.region = NewRegionCollection(t)
	t.az = NewAzCollection(t)

	// Computes
	t.host = NewHostCollection(t)
	t.vm = NewVmCollection(t)

	// Networks
	t.vpc = NewVpcCollection(t)
	t.network = NewNetworkCollection(t)
	t.subnet = NewSubnetCollection(t)
	t.vrouter = NewVrouterCollection(t)
	t.dhcpPort = NewDhcpPortCollection(t)
	t.vinterface = NewVinterfaceCollection(t)
	t.lanIP = NewLanIpCollection(t)
	t.wanIP = NewWanIpCollection(t)

	// Network services
	t.natGateway = NewNatGatewayCollection(t)
	t.lb = NewLbCollection(t)
	t.lbListener = NewLbListenerCollection(t)

	// Storage services
	t.rdsInstance = NewRdsInstanceCollection(t)
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
	t.vmPodNodeConnection = NewVmPodNodeConnectionCollection(t)
	t.process = NewProcessCollection(t)
	t.agent = NewVtapCollection(t)

	return t
}

func (t Tool) Metadata() *rcommon.Metadata { return t.metadata }
func (t Tool) Sequence() int               { return t.sequence }
func (t *Tool) SetSequence(sequence int) {
	t.sequence = sequence
}

// Clouds
func (t Tool) Region() *RegionCollection { return t.region }
func (t Tool) Az() *AzCollection         { return t.az }

// Computes
func (t Tool) Host() *HostCollection             { return t.host }
func (t Tool) Vm() *VmCollection                 { return t.vm } // Networks
func (t Tool) Vpc() *VpcCollection               { return t.vpc }
func (t Tool) Network() *NetworkCollection       { return t.network }
func (t Tool) Subnet() *SubnetCollection         { return t.subnet }
func (t Tool) Vrouter() *VrouterCollection       { return t.vrouter }
func (t Tool) DhcpPort() *DhcpPortCollection     { return t.dhcpPort }
func (t Tool) Vinterface() *VinterfaceCollection { return t.vinterface }
func (t Tool) LanIP() *LanIpCollection           { return t.lanIP }
func (t Tool) WanIP() *WanIpCollection           { return t.wanIP }

// Network services
func (t Tool) NatGateway() *NatGatewayCollection { return t.natGateway }
func (t Tool) Lb() *LbCollection                 { return t.lb }
func (t Tool) LbListener() *LbListenerCollection { return t.lbListener }

// Storage services
func (t Tool) RdsInstance() *RdsInstanceCollection     { return t.rdsInstance }
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
func (t Tool) VmPodNodeConnection() *VmPodNodeConnectionCollection { return t.vmPodNodeConnection }

// Processes
func (t Tool) Process() *ProcessCollection { return t.process }
func (t Tool) Agent() *VtapCollection      { return t.agent }

func (t Tool) GetDeviceVPCIDByLcuuid(deviceType int, deviceLcuuid string) (int, bool) {
	var vpcID int
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		vpcID = t.Vm().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		vpcID = t.Vrouter().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		vpcID = t.DhcpPort().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		vpcID = t.NatGateway().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		vpcID = t.Lb().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		vpcID = t.RdsInstance().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		vpcID = t.RedisInstance().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		vpcID = t.PodNode().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		vpcID = t.PodService().GetByLcuuid(deviceLcuuid).VpcId()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		vpcID = t.Pod().GetByLcuuid(deviceLcuuid).VpcId()
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
		id = t.Vm().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		id = t.Vrouter().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		id = t.DhcpPort().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		id = t.NatGateway().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		id = t.Lb().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		id = t.RdsInstance().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		id = t.RedisInstance().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		id = t.PodNode().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		id = t.PodService().GetByLcuuid(deviceLcuuid).Id()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		id = t.Pod().GetByLcuuid(deviceLcuuid).Id()
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
		lcuuid = t.Vm().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		lcuuid = t.Vrouter().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		lcuuid = t.DhcpPort().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		lcuuid = t.NatGateway().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		lcuuid = t.Lb().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		lcuuid = t.RdsInstance().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		lcuuid = t.RedisInstance().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		lcuuid = t.PodNode().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		lcuuid = t.PodService().GetById(deviceID).Lcuuid()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		lcuuid = t.Pod().GetById(deviceID).Lcuuid()
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
		deviceID = pod.Id()
		return
	}
	agent := t.Agent().GetById(agentID)
	deviceType = ctrlrcommon.VTAP_TYPE_TO_DEVICE_TYPE[agent.AType()]
	deviceID = agent.LaunchServerId()
	return
}
