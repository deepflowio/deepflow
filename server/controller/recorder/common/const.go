/*
 * Copyright (c) 2022 Yunshan Networks
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

package common

import (
	"github.com/deepflowio/deepflow/server/controller/common"
)

const (
	RESOURCE_TYPE_REGION_EN                   = "region"
	RESOURCE_TYPE_AZ_EN                       = "az"
	RESOURCE_TYPE_SUB_DOMAIN_EN               = "sub_domain"
	RESOURCE_TYPE_HOST_EN                     = "host"
	RESOURCE_TYPE_VM_EN                       = "vm"
	RESOURCE_TYPE_VPC_EN                      = "vpc"
	RESOURCE_TYPE_NETWORK_EN                  = "network"
	RESOURCE_TYPE_SUBNET_EN                   = "subnet"
	RESOURCE_TYPE_VROUTER_EN                  = "vrouter"
	RESOURCE_TYPE_ROUTING_TABLE_EN            = "routing_table"
	RESOURCE_TYPE_DHCP_PORT_EN                = "dhcp_port"
	RESOURCE_TYPE_VINTERFACE_EN               = "vinterface"
	RESOURCE_TYPE_WAN_IP_EN                   = "wan_ip"
	RESOURCE_TYPE_LAN_IP_EN                   = "lan_ip"
	RESOURCE_TYPE_FLOATING_IP_EN              = "floating_ip"
	RESOURCE_TYPE_SECURITY_GROUP_EN           = "security_group"
	RESOURCE_TYPE_SECURITY_GROUP_RULE_EN      = "security_group_rule"
	RESOURCE_TYPE_VM_SECURITY_GROUP_EN        = "vm_security_group"
	RESOURCE_TYPE_NAT_GATEWAY_EN              = "nat_gateway"
	RESOURCE_TYPE_NAT_RULE_EN                 = "nat_rule"
	RESOURCE_TYPE_NAT_VM_CONNECTION_EN        = "nat_vm_connection"
	RESOURCE_TYPE_LB_EN                       = "lb"
	RESOURCE_TYPE_LB_VM_CONNECTION_EN         = "lb_vm_connection"
	RESOURCE_TYPE_LB_LISTENER_EN              = "lb_listener"
	RESOURCE_TYPE_LB_TARGET_SERVER_EN         = "lb_target_server"
	RESOURCE_TYPE_PEER_CONNECTION_EN          = "peer_connection"
	RESOURCE_TYPE_CEN_EN                      = "cen"
	RESOURCE_TYPE_RDS_INSTANCE_EN             = "rds_instance"
	RESOURCE_TYPE_REDIS_INSTANCE_EN           = "redis_instance"
	RESOURCE_TYPE_POD_CLUSTER_EN              = "pod_cluster"
	RESOURCE_TYPE_POD_NODE_EN                 = "pod_node"
	RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN   = "vm_pod_node_connection"
	RESOURCE_TYPE_POD_NAMESPACE_EN            = "pod_namespace"
	RESOURCE_TYPE_POD_INGRESS_EN              = "pod_ingress"
	RESOURCE_TYPE_POD_INGRESS_RULE_EN         = "pod_ingress_rule"
	RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN = "pod_ingress_rule_backend"
	RESOURCE_TYPE_POD_SERVICE_EN              = "pod_service"
	RESOURCE_TYPE_POD_SERVICE_PORT_EN         = "pod_service_port"
	RESOURCE_TYPE_POD_GROUP_EN                = "pod_group"
	RESOURCE_TYPE_POD_GROUP_PORT_EN           = "pod_group_port"
	RESOURCE_TYPE_POD_REPLICA_SET_EN          = "pod_replica_set"
	RESOURCE_TYPE_POD_EN                      = "pod"
	RESOURCE_TYPE_PROCESS_EN                  = "process"
)

const (
	IPV4_DEFAULT_PREFIX  = "0.0.0.0"
	IPV4_DEFAULT_NETMASK = 32
	IPV4_DEFAULT_GATEWAY = "0.0.0.0"
	IPV6_DEFAULT_PREFIX  = "::"
	IPV6_DEFAULT_NETMASK = 128
	IPV6_DEFAULT_GATEWAY = "::"
)

const (
	VROUTER_STATE_RUNNING = 7
	WAN_IP_ISP            = 7
	PUBLIC_NETWORK_LCUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

var DEVICE_TYPE_INT_TO_STR = map[int]string{
	common.VIF_DEVICE_TYPE_HOST:           RESOURCE_TYPE_HOST_EN,
	common.VIF_DEVICE_TYPE_VM:             RESOURCE_TYPE_VM_EN,
	common.VIF_DEVICE_TYPE_VROUTER:        RESOURCE_TYPE_VROUTER_EN,
	common.VIF_DEVICE_TYPE_DHCP_PORT:      RESOURCE_TYPE_DHCP_PORT_EN,
	common.VIF_DEVICE_TYPE_NAT_GATEWAY:    RESOURCE_TYPE_NAT_GATEWAY_EN,
	common.VIF_DEVICE_TYPE_LB:             RESOURCE_TYPE_LB_EN,
	common.VIF_DEVICE_TYPE_RDS_INSTANCE:   RESOURCE_TYPE_RDS_INSTANCE_EN,
	common.VIF_DEVICE_TYPE_REDIS_INSTANCE: RESOURCE_TYPE_REDIS_INSTANCE_EN,
	common.VIF_DEVICE_TYPE_POD_NODE:       RESOURCE_TYPE_POD_NODE_EN,
	common.VIF_DEVICE_TYPE_POD_SERVICE:    RESOURCE_TYPE_POD_SERVICE_EN,
	common.VIF_DEVICE_TYPE_POD:            RESOURCE_TYPE_POD_EN,
	common.PROCESS_INSTANCE_TYPE:          RESOURCE_TYPE_PROCESS_EN,
}
