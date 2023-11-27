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

package pubsub

import (
	"github.com/deepflowio/deepflow/server/controller/common"
)

const (
	PubSubTypeAllDomains = iota
	PubSubTypeDomain
	PubSubTypeRegion
	PubSubTypeAZ
	PubSubTypeSubDomain
	PubSubTypeHost
	PubSubTypeVM
	PubSubTypeVMPodNodeConnection
	PubSubTypeVPC
	PubSubTypeNetwork
	PubSubTypeSubnet
	PubSubTypeVRouter
	PubSubTypeRoutingTable
	PubSubTypeDHCPPort
	PubSubTypeVInterface
	PubSubTypeFloatingIP
	PubSubTypeWANIP
	PubSubTypeLANIP
	PubSubTypeVIP
	PubSubTypeSecurityGroup
	PubSubTypeVMSecurityGroup
	PubSubTypeSecurityGroupRule
	PubSubTypeNATGateway
	PubSubTypeNATRule
	PubSubTypeNATVMConnection
	PubSubTypeLB
	PubSubTypeLBListener
	PubSubTypeLBTargetServer
	PubSubTypeLBVMConnection
	PubSubTypePeerConnection
	PubSubTypeCEN
	PubSubTypeRDSInstance
	PubSubTypeRedisInstance
	PubSubTypePodCluster
	PubSubTypePodNode
	PubSubTypePodNamespace
	PubSubTypePodIngress
	PubSubTypePodIngressRule
	PubSubTypePodIngressRuleBackend
	PubSubTypePodService
	PubSubTypePodServicePort
	PubSubTypePodGroup
	PubSubTypePodGroupPort
	PubSubTypePodReplicaSet
	PubSubTypePod
	PubSubTypeProcess
	PubSubTypePrometheusTarget
)

var ResourceTypeToPubsubType = map[string]int{
	common.RESOURCE_TYPE_REGION_EN:                   PubSubTypeRegion,
	common.RESOURCE_TYPE_AZ_EN:                       PubSubTypeAZ,
	common.RESOURCE_TYPE_SUB_DOMAIN_EN:               PubSubTypeSubDomain,
	common.RESOURCE_TYPE_HOST_EN:                     PubSubTypeHost,
	common.RESOURCE_TYPE_VM_EN:                       PubSubTypeVM,
	common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN:   PubSubTypeVMPodNodeConnection,
	common.RESOURCE_TYPE_VPC_EN:                      PubSubTypeVPC,
	common.RESOURCE_TYPE_NETWORK_EN:                  PubSubTypeNetwork,
	common.RESOURCE_TYPE_SUBNET_EN:                   PubSubTypeSubnet,
	common.RESOURCE_TYPE_VROUTER_EN:                  PubSubTypeVRouter,
	common.RESOURCE_TYPE_ROUTING_TABLE_EN:            PubSubTypeRoutingTable,
	common.RESOURCE_TYPE_DHCP_PORT_EN:                PubSubTypeDHCPPort,
	common.RESOURCE_TYPE_FLOATING_IP_EN:              PubSubTypeFloatingIP,
	common.RESOURCE_TYPE_WAN_IP_EN:                   PubSubTypeWANIP,
	common.RESOURCE_TYPE_LAN_IP_EN:                   PubSubTypeLANIP,
	common.RESOURCE_TYPE_VIP_EN:                      PubSubTypeVIP,
	common.RESOURCE_TYPE_SECURITY_GROUP_EN:           PubSubTypeSecurityGroup,
	common.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN:      PubSubTypeSecurityGroupRule,
	common.RESOURCE_TYPE_NAT_GATEWAY_EN:              PubSubTypeNATGateway,
	common.RESOURCE_TYPE_NAT_RULE_EN:                 PubSubTypeNATRule,
	common.RESOURCE_TYPE_NAT_VM_CONNECTION_EN:        PubSubTypeNATVMConnection,
	common.RESOURCE_TYPE_LB_EN:                       PubSubTypeLB,
	common.RESOURCE_TYPE_LB_LISTENER_EN:              PubSubTypeLBListener,
	common.RESOURCE_TYPE_LB_TARGET_SERVER_EN:         PubSubTypeLBTargetServer,
	common.RESOURCE_TYPE_LB_VM_CONNECTION_EN:         PubSubTypeLBVMConnection,
	common.RESOURCE_TYPE_PEER_CONNECTION_EN:          PubSubTypePeerConnection,
	common.RESOURCE_TYPE_CEN_EN:                      PubSubTypeCEN,
	common.RESOURCE_TYPE_RDS_INSTANCE_EN:             PubSubTypeRDSInstance,
	common.RESOURCE_TYPE_REDIS_INSTANCE_EN:           PubSubTypeRedisInstance,
	common.RESOURCE_TYPE_POD_CLUSTER_EN:              PubSubTypePodCluster,
	common.RESOURCE_TYPE_POD_NODE_EN:                 PubSubTypePodNode,
	common.RESOURCE_TYPE_POD_NAMESPACE_EN:            PubSubTypePodNamespace,
	common.RESOURCE_TYPE_POD_INGRESS_EN:              PubSubTypePodIngress,
	common.RESOURCE_TYPE_POD_INGRESS_RULE_EN:         PubSubTypePodIngressRule,
	common.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN: PubSubTypePodIngressRuleBackend,
	common.RESOURCE_TYPE_POD_SERVICE_EN:              PubSubTypePodService,
	common.RESOURCE_TYPE_POD_SERVICE_PORT_EN:         PubSubTypePodServicePort,
	common.RESOURCE_TYPE_POD_GROUP_EN:                PubSubTypePodGroup,
	common.RESOURCE_TYPE_POD_GROUP_PORT_EN:           PubSubTypePodGroupPort,
	common.RESOURCE_TYPE_POD_REPLICA_SET_EN:          PubSubTypePodReplicaSet,
	common.RESOURCE_TYPE_POD_EN:                      PubSubTypePod,
	common.RESOURCE_TYPE_PROCESS_EN:                  PubSubTypeProcess,
	common.RESOURCE_TYPE_PROMETHEUS_TARGET_EN:        PubSubTypePrometheusTarget,
}
