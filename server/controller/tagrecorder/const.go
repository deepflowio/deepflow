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

package tagrecorder

import (
	"github.com/deepflowys/deepflow/server/controller/common"
)

const (
	RESOURCE_TYPE_REGION            = "region"
	RESOURCE_TYPE_AZ                = "az"
	RESOURCE_TYPE_HOST              = "host"
	RESOURCE_TYPE_VPC               = "epc"
	RESOURCE_TYPE_NAT_GATEWAY       = "nat_gateway"
	RESOURCE_TYPE_LB                = "lb"
	RESOURCE_TYPE_VL2               = "vl2"
	RESOURCE_TYPE_REDIS             = "redis_instance"
	RESOURCE_TYPE_RDS               = "rds_instance"
	RESOURCE_TYPE_VM                = "vm"
	RESOURCE_TYPE_VGW               = "vgateway"
	RESOURCE_TYPE_DHCP_PORT         = "dhcp_port"
	RESOURCE_TYPE_IP                = "ip"
	RESOURCE_TYPE_POD_CLUSTER       = "pod_cluster"
	RESOURCE_TYPE_POD_NODE          = "pod_node"
	RESOURCE_TYPE_POD_NAMESPACE     = "pod_namespace"
	RESOURCE_TYPE_POD_GROUP         = "pod_group"
	RESOURCE_TYPE_POD_SERVICE       = "pod_service"
	RESOURCE_TYPE_POD               = "pod"
	RESOURCE_TYPE_INTERNET          = "internet"
	RESOURCE_TYPE_VINTERFACE        = "vinterface"
	RESOURCE_TYPE_WANIP             = "wan_ip"
	RESOURCE_TYPE_LANIP             = "lan_ip"
	RESOURCE_TYPE_NAT_RULE          = "nat_rule"
	RESOURCE_TYPE_NAT_VM_CONNECTION = "nat_vm_connection"
	RESOURCE_TYPE_LB_LISTENER       = "lb_listener"
	RESOURCE_TYPE_LB_TARGET_SERVER  = "lb_target_server"
	RESOURCE_TYPE_LB_VM_CONNECTION  = "lb_vm_connection"
	RESOURCE_TYPE_POD_GROUP_PORT    = "pod_group_port"
	RESOURCE_TYPE_POD_INGRESS       = "pod_ingress"
)

const (
	RESOURCE_TYPE_CH_K8S_LABEL   = "ch_k8s_label"
	RESOURCE_TYPE_CH_REGION      = "ch_region"
	RESOURCE_TYPE_CH_AZ          = "ch_az"
	RESOURCE_TYPE_CH_VPC         = "ch_vpc"
	RESOURCE_TYPE_CH_DEVICE      = "ch_device"
	RESOURCE_TYPE_CH_IP_RELATION = "ch_ip_relation"
	RESOURCE_TYPE_CH_IP_RESOURCE = "ch_ip_resource"

	RESOURCE_TYPE_CH_POD_PORT       = "ch_pod_port"
	RESOURCE_TYPE_CH_POD_NODE_PORT  = "ch_pod_node_port"
	RESOURCE_TYPE_CH_POD_GROUP_PORT = "ch_pod_group_port"
	RESOURCE_TYPE_CH_IP_PORT        = "ch_ip_port"
	RESOURCE_TYPE_CH_DEVICE_PORT    = "ch_device_port"

	RESOURCE_TYPE_CH_NETWORK       = "ch_network"
	RESOURCE_TYPE_CH_POD           = "ch_pod"
	RESOURCE_TYPE_CH_POD_GROUP     = "ch_pod_group"
	RESOURCE_TYPE_CH_POD_NAMESPACE = "ch_pod_namespace"
	RESOURCE_TYPE_CH_POD_NODE      = "ch_pod_node"
	RESOURCE_TYPE_TAP_TYPE         = "ch_tap_type"
	RESOURCE_TYPE_CH_VTAP          = "ch_vtap"
	RESOURCE_TYPE_CH_VTAP_PORT     = "ch_vtap_port"
	RESOURCE_TYPE_CH_LB_LISTENER   = "ch_lb_listener"
)

const (
	CH_DICTIONARY_REGION        = "region_map"
	CH_DICTIONARY_AZ            = "az_map"
	CH_DICTIONARY_DEVICE        = "device_map" // vm, host, vgw, dhcp_port, pod, pod_service, pod_node, redis, rds, lb, nat
	CH_DICTIONARY_VPC           = "l3_epc_map"
	CH_DICTIONARY_VL2           = "subnet_map"
	CH_DICTIONARY_POD_CLUSTER   = "pod_cluster_map"
	CH_DICTIONARY_POD_NAMESPACE = "pod_ns_map"
	CH_DICTIONARY_POD_NODE      = "pod_node_map"
	CH_DICTIONARY_POD_GROUP     = "pod_group_map"
	CH_DICTIONARY_POD           = "pod_map"
	CH_DICTIONARY_VTAP_PORT     = "vtap_port_map"
	CH_DICTIONARY_TAP_TYPE      = "tap_type_map"
	CH_DICTIONARY_VTAP          = "vtap_map"
	CH_DICTIONARY_LB_LISTENER   = "lb_listener_map"
	CH_DICTIONARY_K8S_LABEL     = "k8s_label_map"

	CH_DICTIONARY_POD_NODE_PORT  = "pod_node_port_map"
	CH_DICTIONARY_POD_GROUP_PORT = "pod_group_port_map"
	CH_DICTIONARY_POD_PORT       = "pod_port_map"
	CH_DICTIONARY_DEVICE_PORT    = "device_port_map"
	CH_DICTIONARY_IP_PORT        = "ip_port_map"
	CH_DICTIONARY_SERVER_PORT    = "server_port_map"

	CH_DICTIONARY_IP_RELATION = "ip_relation_map"
	CH_DICTIONARY_IP_RESOURCE = "ip_resource_map"
)

const (
	CH_DEVICE_TYPE_IP        = 64000
	CH_DEVICE_TYPE_INTERNET  = 63999
	CH_DEVICE_TYPE_POD_GROUP = 101
	CH_DEVICE_TYPE_SERVICE   = 102

	CH_VTAP_PORT_TYPE_TAP_MAC = 1
	CH_VTAP_PORT_TYPE_MAC     = 2
	CH_VTAP_PORT_NAME_MAX     = 10
)

var CH_IP_RESOURCE_TAGS = []string{
	"region_id", "region_name", "az_id", "az_name", "host_id", "host_name",
	"chost_id", "chost_name", "vpc_id", "vpc_name", "subnet_id", "subnet_name",
	"router_id", "router_name", "dhcpgw_id", "dhcpgw_name", "lb_id", "lb_name",
	"lb_listener_id", "lb_listener_name", "natgw_id", "natgw_name", "redis_id",
	"redis_name", "rds_id", "rds_name", "pod_cluster_id", "pod_cluster_name",
	"pod_ns_id", "pod_ns_name", "pod_node_id", "pod_node_name",
	"pod_ingress_id", "pod_ingress_name", "pod_service_id", "pod_service_name",
	"pod_group_id", "pod_group_name", "pod_id", "pod_name",
}

const (
	CREATE_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_VPC_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `uid` String\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_TAP_TYPE_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `value` UInt64,\n" +
		"    `name` String\n" +
		")\n" +
		"PRIMARY KEY value\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_VTAP_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `type` Int64,\n" +
		"    `icon_id` Int64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_DEVICE_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `devicetype` UInt64,\n" +
		"    `deviceid` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `uid` String\n" +
		")\n" +
		"PRIMARY KEY devicetype, deviceid\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_VTAP_PORT_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `vtap_id` UInt64,\n" +
		"    `tap_port` UInt64,\n" +
		"    `name` String,\n" +
		"    `host_id` Int64,\n" +
		"    `host_name` String,\n" +
		"    `device_type` UInt64,\n" +
		"    `device_id` UInt64,\n" +
		"    `device_name` String,\n" +
		"    `icon_id` Int64\n" +
		")\n" +
		"PRIMARY KEY vtap_id, tap_port\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_PORT_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `protocol` UInt64,\n" +
		"    `port` UInt64,\n" +
		"    `port_lb_id` UInt64,\n" +
		"    `port_lb_name` String,\n" +
		"    `port_lb_listener_id` UInt64,\n" +
		"    `port_lb_listener_name` String,\n" +
		"    `port_pod_service_id` UInt64,\n" +
		"    `port_pod_service_name` String\n" +
		")\n" +
		"PRIMARY KEY id, protocol, port\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_IP_PORT_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `ip` String,\n" +
		"    `subnet_id` UInt64,\n" +
		"    `protocol` UInt64,\n" +
		"    `port` UInt64,\n" +
		"    `port_lb_id` UInt64,\n" +
		"    `port_lb_name` String,\n" +
		"    `port_lb_listener_id` UInt64,\n" +
		"    `port_lb_listener_name` String,\n" +
		"    `port_pod_service_id` UInt64,\n" +
		"    `port_pod_service_name` String\n" +
		")\n" +
		"PRIMARY KEY ip, subnet_id, protocol, port\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_DEVICE_PORT_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `devicetype` UInt64,\n" +
		"    `deviceid` UInt64,\n" +
		"    `protocol` UInt64,\n" +
		"    `port` UInt64,\n" +
		"    `port_lb_id` UInt64,\n" +
		"    `port_lb_name` String,\n" +
		"    `port_lb_listener_id` UInt64,\n" +
		"    `port_lb_listener_name` String,\n" +
		"    `port_pod_service_id` UInt64,\n" +
		"    `port_pod_service_name` String\n" +
		")\n" +
		"PRIMARY KEY devicetype, deviceid, protocol, port\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_SERVER_PORT_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `server_port` UInt64,\n" +
		"    `server_port_name` String\n" +
		")\n" +
		"PRIMARY KEY server_port\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_IP_RELATION_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `ip` String,\n" +
		"    `natgw_id` UInt64,\n" +
		"    `natgw_name` String,\n" +
		"    `lb_id` UInt64,\n" +
		"    `lb_name` String,\n" +
		"    `lb_listener_id` UInt64,\n" +
		"    `lb_listener_name` String,\n" +
		"    `pod_ingress_id` UInt64,\n" +
		"    `pod_ingress_name` String,\n" +
		"    `pod_service_id` UInt64,\n" +
		"    `pod_service_name` String\n" +
		")\n" +
		"PRIMARY KEY l3_epc_id, ip\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_LB_LISTENER_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(FLAT())"
	CREATE_K8S_LABEL_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `pod_id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY pod_id, key\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
	CREATE_IP_RESOURCE_DICTIONARY_SQL = "CREATE DICTIONARY %s.%s\n" +
		"(\n" +
		"    `ip` String,\n" +
		"    `subnet_id` UInt64,\n" +
		"    `subnet_name` String,\n" +
		"    `region_id` UInt64,\n" +
		"    `region_name` String,\n" +
		"    `az_id` UInt64,\n" +
		"    `az_name` String,\n" +
		"    `host_id` UInt64,\n" +
		"    `host_name` String,\n" +
		"    `chost_id` UInt64,\n" +
		"    `chost_name` String,\n" +
		"    `vpc_id` UInt64,\n" +
		"    `vpc_name` String,\n" +
		"    `router_id` UInt64,\n" +
		"    `router_name` String,\n" +
		"    `dhcpgw_id` UInt64,\n" +
		"    `dhcpgw_name` String,\n" +
		"    `lb_id` UInt64,\n" +
		"    `lb_name` String,\n" +
		"    `lb_listener_id` UInt64,\n" +
		"    `lb_listener_name` String,\n" +
		"    `natgw_id` UInt64,\n" +
		"    `natgw_name` String,\n" +
		"    `redis_id` UInt64,\n" +
		"    `redis_name` String,\n" +
		"    `rds_id` UInt64,\n" +
		"    `rds_name` String,\n" +
		"    `pod_cluster_id` UInt64,\n" +
		"    `pod_cluster_name` String,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `pod_ns_name` String,\n" +
		"    `pod_node_id` UInt64,\n" +
		"    `pod_node_name` String,\n" +
		"    `pod_ingress_id` UInt64,\n" +
		"    `pod_ingress_name` String,\n" +
		"    `pod_service_id` UInt64,\n" +
		"    `pod_service_name` String,\n" +
		"    `pod_group_id` UInt64,\n" +
		"    `pod_group_name` String,\n" +
		"    `pod_id` UInt64,\n" +
		"    `pod_name` String\n" +
		")\n" +
		"PRIMARY KEY ip, subnet_id\n" +
		"SOURCE(MYSQL(PORT %s USER '%s' PASSWORD '%s' %s DB %s TABLE %s INVALIDATE_QUERY 'select updated_at from %s order by updated_at desc limit 1'))\n" +
		"LIFETIME(MIN 0 MAX 60)\n" +
		"LAYOUT(COMPLEX_KEY_HASHED())"
)

var DBNodeTypeToResourceType = map[string]string{
	"region":      RESOURCE_TYPE_REGION,
	"az":          RESOURCE_TYPE_AZ,
	"host":        RESOURCE_TYPE_HOST,
	"l3_epc":      RESOURCE_TYPE_VPC,
	"subnet":      RESOURCE_TYPE_VL2,
	"vm":          RESOURCE_TYPE_VM,
	"router":      RESOURCE_TYPE_VGW,
	"dhcp_port":   RESOURCE_TYPE_DHCP_PORT,
	"nat_gateway": RESOURCE_TYPE_NAT_GATEWAY,
	"lb":          RESOURCE_TYPE_LB,
	"redis":       RESOURCE_TYPE_REDIS,
	"rds":         RESOURCE_TYPE_RDS,
	"pod_cluster": RESOURCE_TYPE_POD_CLUSTER,
	"pod_node":    RESOURCE_TYPE_POD_NODE,
	"pod_ns":      RESOURCE_TYPE_POD_NAMESPACE,
	"pod_group":   RESOURCE_TYPE_POD_GROUP,
	"pod_service": RESOURCE_TYPE_POD_SERVICE,
	"pod":         RESOURCE_TYPE_POD,
	"ip":          RESOURCE_TYPE_IP,
	"internet":    RESOURCE_TYPE_INTERNET,
}

// icon名称不会重复
var IconNameToDomainType = map[string][]int{
	"OpenStack":                {common.OPENSTACK},
	"vSphere":                  {common.VSPHERE},
	"NSP":                      {common.NSP},
	common.TENCENT_CH:          {common.TENCENT, common.TENCENT_TCE},
	"AWS":                      {common.AWS},
	common.PINGAN_CH:           {common.PINGAN},
	"ZStack":                   {common.ZSTACK},
	common.ALIYUN_CH:           {common.ALIYUN, common.APSARA_STACK},
	"Kubernetes":               {common.KUBERNETES},
	common.HUAWEI_CH:           {common.HUAWEI, common.HUAWEI_PRIVATE},
	common.QINGCLOUD_CH:        {common.QINGCLOUD, common.QINGCLOUD_PRIVATE},
	common.MICROSOFT_CH:        {common.AZURE, common.CMB_CMDB, common.MICROSOFT_ACS},
	common.KINGSOFT_PRIVATE_CH: {common.KINGSOFT_PRIVATE},
	common.BAIDU_BCE_CH:        {common.BAIDU_BCE},
}

var CREATE_SQL_MAP = map[string]string{
	CH_DICTIONARY_REGION:         CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_AZ:             CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_VPC:            CREATE_VPC_DICTIONARY_SQL,
	CH_DICTIONARY_VL2:            CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_POD_CLUSTER:    CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_POD_NAMESPACE:  CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_POD_NODE:       CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_POD_GROUP:      CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_POD:            CREATE_DICTIONARY_SQL,
	CH_DICTIONARY_DEVICE:         CREATE_DEVICE_DICTIONARY_SQL,
	CH_DICTIONARY_VTAP_PORT:      CREATE_VTAP_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_TAP_TYPE:       CREATE_TAP_TYPE_DICTIONARY_SQL,
	CH_DICTIONARY_VTAP:           CREATE_VTAP_DICTIONARY_SQL,
	CH_DICTIONARY_POD_NODE_PORT:  CREATE_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_POD_GROUP_PORT: CREATE_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_POD_PORT:       CREATE_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_DEVICE_PORT:    CREATE_DEVICE_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_IP_PORT:        CREATE_IP_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_SERVER_PORT:    CREATE_SERVER_PORT_DICTIONARY_SQL,
	CH_DICTIONARY_IP_RELATION:    CREATE_IP_RELATION_DICTIONARY_SQL,
	CH_DICTIONARY_LB_LISTENER:    CREATE_LB_LISTENER_DICTIONARY_SQL,
	CH_DICTIONARY_K8S_LABEL:      CREATE_K8S_LABEL_DICTIONARY_SQL,
	CH_DICTIONARY_IP_RESOURCE:    CREATE_IP_RESOURCE_DICTIONARY_SQL,
}

var VTAP_TYPE_TO_DEVICE_TYPE = map[int]int{
	common.VTAP_TYPE_KVM:        common.VIF_DEVICE_TYPE_HOST,
	common.VTAP_TYPE_EXSI:       common.VIF_DEVICE_TYPE_HOST,
	common.VTAP_TYPE_WORKLOAD_V: common.VIF_DEVICE_TYPE_VM,
	common.VTAP_TYPE_WORKLOAD_P: common.VIF_DEVICE_TYPE_VM,
	common.VTAP_TYPE_POD_HOST:   common.VIF_DEVICE_TYPE_POD_NODE,
	common.VTAP_TYPE_POD_VM:     common.VIF_DEVICE_TYPE_POD_NODE,
	common.VTAP_TYPE_HYPER_V:    common.VIF_DEVICE_TYPE_HOST,
}
