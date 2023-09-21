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

package tag

const (
	VIF_DEVICE_TYPE_INTERNET                        = 0
	VIF_DEVICE_TYPE_VM                              = 1
	VIF_DEVICE_TYPE_VROUTER                         = 5
	VIF_DEVICE_TYPE_HOST                            = 6
	VIF_DEVICE_TYPE_DHCP_PORT                       = 9
	VIF_DEVICE_TYPE_POD                             = 10
	VIF_DEVICE_TYPE_POD_SERVICE                     = 11
	VIF_DEVICE_TYPE_REDIS_INSTANCE                  = 12
	VIF_DEVICE_TYPE_RDS_INSTANCE                    = 13
	VIF_DEVICE_TYPE_POD_NODE                        = 14
	VIF_DEVICE_TYPE_LB                              = 15
	VIF_DEVICE_TYPE_NAT_GATEWAY                     = 16
	VIF_DEVICE_TYPE_POD_GROUP                       = 101
	VIF_DEVICE_TYPE_SERVICE                         = 102
	VIF_DEVICE_TYPE_POD_GROUP_DEPLOYMENT            = 130
	VIF_DEVICE_TYPE_POD_GROUP_STATEFULSET           = 131
	VIF_DEVICE_TYPE_POD_GROUP_RC                    = 132
	VIF_DEVICE_TYPE_POD_GROUP_DAEMON_SET            = 133
	VIF_DEVICE_TYPE_POD_GROUP_REPLICASET_CONTROLLER = 134
	VIF_DEVICE_TYPE_IP                              = 255
)

const (
	TAP_PORT_MAC_0 = 0
	TAP_PORT_MAC_1 = 1
	TAP_PORT_IPV4  = 2
)

var TAG_RESOURCE_TYPE_DEFAULT = []string{
	"region", "az", "pod_node", "pod_ns",
	"pod_group", "pod", "pod_cluster", "subnet",
}
var TAG_RESOURCE_TYPE_AUTO = []string{"resource_gl0", "resource_gl1", "resource_gl2"}

var AutoMap = map[string]int{
	"chost":       VIF_DEVICE_TYPE_VM,
	"router":      VIF_DEVICE_TYPE_VROUTER,
	"host":        VIF_DEVICE_TYPE_HOST,
	"dhcpgw":      VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         VIF_DEVICE_TYPE_RDS_INSTANCE,
	"pod_node":    VIF_DEVICE_TYPE_POD_NODE,
	"lb":          VIF_DEVICE_TYPE_LB,
	"natgw":       VIF_DEVICE_TYPE_NAT_GATEWAY,
}

var AutoPodMap = map[string]int{
	"pod": VIF_DEVICE_TYPE_POD,
}

var AutoPodGroupMap = map[string]int{
	"pod_group": VIF_DEVICE_TYPE_POD_GROUP,
}

var AutoServiceMap = map[string]int{
	"pod_group":              VIF_DEVICE_TYPE_POD_GROUP,
	"deployment":             VIF_DEVICE_TYPE_POD_GROUP_DEPLOYMENT,
	"stateful_set":           VIF_DEVICE_TYPE_POD_GROUP_STATEFULSET,
	"replication_controller": VIF_DEVICE_TYPE_POD_GROUP_RC,
	"daemon_set":             VIF_DEVICE_TYPE_POD_GROUP_DAEMON_SET,
	"replica_set_controller": VIF_DEVICE_TYPE_POD_GROUP_REPLICASET_CONTROLLER,
	"service":                VIF_DEVICE_TYPE_SERVICE,
}

var PodGroupTypeSlice = []string{
	"deployment", "stateful_set", "replication_controller", "daemon_set",
	"replica_set_controller",
}

var NoLanguageTag = []string{
	"ip_type", "l7_ip_protocol", "server_port", "span_kind", "tcp_flags_bit",
	"tunnel_tier", "l7_protocol", "eth_type", "l4_signal_source", "l7_signal_source", "protocol", "tunnel_type",
}
