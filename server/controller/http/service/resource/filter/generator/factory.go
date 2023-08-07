/**
 * Copyright (c) 2023 Yunshan Networks
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

package generator

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
)

type RequiredConfigs struct {
	FPermit config.FPermit
}

// Get returns a filter generator instance of specified resource type
func Get(resourceType string, cfg *RequiredConfigs) FilterGenerator {
	switch resourceType {
	case common.RESOURCE_TYPE_REGION_EN:
		return NewRegion()
	case common.RESOURCE_TYPE_AZ_EN:
		return NewAZ()
	case common.RESOURCE_TYPE_HOST_EN:
		return NewHost()
	case common.RESOURCE_TYPE_VM_EN:
		return NewVM(cfg.FPermit)
	case common.RESOURCE_TYPE_VPC_EN:
		return NewVPC(cfg.FPermit)
	case common.RESOURCE_TYPE_VROUTER_EN:
		return NewVRouter(cfg.FPermit)
	case common.RESOURCE_TYPE_ROUTING_TABLE_EN:
		return NewRoutingTable(cfg.FPermit)
	case common.RESOURCE_TYPE_DHCP_PORT_EN:
		return NewDHCPPort(cfg.FPermit)
	case common.RESOURCE_TYPE_VINTERFACE_EN:
		return NewVInterface(cfg.FPermit)
	case common.RESOURCE_TYPE_IP_EN:
		return NewIP(cfg.FPermit)
	case common.RESOURCE_TYPE_SECURITY_GROUP_EN:
		return NewSecurityGroup()
	case common.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN:
		return NewSecurityGroupRule()
	case common.RESOURCE_TYPE_NAT_GATEWAY_EN:
		return NewNATGateway(cfg.FPermit)
	case common.RESOURCE_TYPE_NAT_RULE_EN:
		return NewNATRule(cfg.FPermit)
	case common.RESOURCE_TYPE_LB_EN:
		return NewLB(cfg.FPermit)
	case common.RESOURCE_TYPE_LB_LISTENER_EN:
		return NewLBListener(cfg.FPermit)
	case common.RESOURCE_TYPE_LB_RULE_EN:
		return NewLBRule(cfg.FPermit)
	case common.RESOURCE_TYPE_PEER_CONNECTION_EN:
		return NewPeerConnection()
	case common.RESOURCE_TYPE_CEN_EN:
		return NewCEN()
	case common.RESOURCE_TYPE_POD_CLUSTER_EN:
		return NewPodCluster(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_NODE_EN:
		return NewPodNode(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_NAMESPACE_EN:
		return NewPodNamespace(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_INGRESS_EN:
		return NewPodIngress(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_INGRESS_RULE_EN:
		return NewPodIngressRule(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		return NewPodService(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_SERVICE_PORT_EN:
		return NewPodServicePort(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_GROUP_EN:
		return NewPodGroup(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_GROUP_PORT_EN:
		return NewPodGroupPort(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_REPLICA_SET_EN:
		return NewPodReplicaSet(cfg.FPermit)
	case common.RESOURCE_TYPE_POD_EN:
		return NewPod(cfg.FPermit)
	case common.RESOURCE_TYPE_PROCESS_EN:
		return NewProcess()
	default:
		return nil
	}

}
