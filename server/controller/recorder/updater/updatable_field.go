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

package updater

var ResourceTypeToUpdatableFields = map[string][]string{
	"region":              {"name", "label"},
	"az":                  {"name", "label", "region"},
	"sub_domain":          {},
	"host":                {"name", "region", "az", "ip", "htype", "vcpu_num", "mem_total", "extra_info"},
	"vm":                  {"name", "state", "launch_server", "epc_id", "az", "region", "htype", "label"},
	"vpc":                 {"name", "cidr", "label", "tunnel_id", "region"},
	"network":             {"name", "label", "segmentation_id", "region", "az", "epc_id", "net_type", "tunnel_id"},
	"subnet":              {"name", "label"},
	"vrouter":             {"name", "label", "epc_id", "region"},
	"routing_table":       {"destination", "nexthop_type", "nexthop"},
	"dhcp_port":           {"name", "region", "az"},
	"vinterface":          {"name", "subnetid", "tap_mac", "region"},
	"wan_ip":              {"region"},
	"floating_ip":         {"region"},
	"security_group":      {"name", "label", "region"},
	"security_group_rule": {"priority", "ethertype", "remote_port_range", "remote", "local"},
	"vm_security_group":   {"priority"},
	"nat_gateway":         {"name", "floating_ips", "region"},
	"lb":                  {"name", "model", "vip", "region"},
	"lb_listener":         {"name", "port", "protocol", "ips", "snat_ips"},
	"lb_target_server":    {"port", "protocol", "ip"},
	"peer_connection":     {"name", "remote_region_id", "local_region_id"},
	"cen":                 {"name", "epc_ids"},
	"rds_instance":        {"name", "state", "series", "model", "region"},
	"redis_instance":      {"name", "state", "public_host", "region"},
	"pod_cluser":          {"name", "region", "az", "cluster_name"},
	"pod_node":            {"state", "az", "region", "vcpu_num", "mem_total"},
	"pod_namespace":       {"region", "az"},
	"pod_ingress":         {"name", "region", "az"},
	"pod_service":         {"name", "selector", "pod_ingress_id", "service_cluster_ip", "region", "az"},
	"pod_service_port":    {"name"},
	"pod_group":           {"name", "pod_num", "label", "region", "az", "type"},
	"pod_group_port":      {"name"},
	"pod_replica_set":     {"name", "pod_num", "region", "az"},
	"pod":                 {"name", "state", "region", "az", "epc_id", "pod_rs_id", "pod_node_id", "created_at"},
}

// xxxUpdatableStructFieldToDBField
// cloud/diff_base 结构体字段到数据库字段的映射，用于清晰实现检查更新的逻辑

var regionUpdatableStructFieldToDBField = map[string]string{
	"Name":  "name",
	"Label": "label",
}

var azUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"Label":        "label",
	"RegionLcuuid": "region",
}

var hostUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
	"IP":           "ip",
	"HType":        "htype",
	"VCPUNum":      "vcpu_num",
	"MemTotal":     "mem_total",
	"ExtraInfo":    "extra_info",
}

var vmUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"State":        "state",
	"LaunchServer": "launch_server",
	"VPCLcuuid":    "epc_id",
	"AZLcuuid":     "az",
	"RegionLcuuid": "region",
	"HType":        "htype",
	"Label":        "label",
}

var vpcUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"CIDR":         "cidr",
	"Label":        "label",
	"TunnelID":     "tunnel_id",
	"RegionLcuuid": "region",
}

var networkUpdatableStructFieldToDBField = map[string]string{
	"Name":           "name",
	"Label":          "label",
	"SegmentationID": "segmentation_id",
	"RegionLcuuid":   "region",
	"AZLcuuid":       "az",
	"VPCLcuuid":      "epc_id",
	"NetType":        "net_type",
	"TunnelID":       "tunnel_id",
}

var subnetUpdatableStructFieldToDBField = map[string]string{
	"Name":  "name",
	"Label": "label",
}

var vrouterUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"Label":        "label",
	"VPCLcuuid":    "epc_id",
	"RegionLcuuid": "region",
}

var routingTableUpdatableStructFieldToDBField = map[string]string{
	"Destination": "destination",
	"NexthopType": "nexthop_type",
	"Nexthop":     "nexthop",
}

var dhcpPortUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
}

var vinterfaceUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"SubnetLcuuid": "subnetid",
	"TapMac":       "tap_mac",
	"RegionLcuuid": "region",
}

var wanIpUpdatableStructFieldToDBField = map[string]string{
	"RegionLcuuid": "region",
}

var floatingIpUpdatableStructFieldToDBField = map[string]string{
	"RegionLcuuid": "region",
}

var securityGroupUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"Label":        "label",
	"RegionLcuuid": "region",
}

var securityGroupRuleUpdatableStructFieldToDBField = map[string]string{
	"Priority":        "priority",
	"Ethertype":       "ethertype",
	"RemotePortRange": "remote_port_range",
	"Remote":          "remote",
	"Local":           "local",
}

var vmSecurityGroupUpdatableStructFieldToDBField = map[string]string{
	"Priority": "priority",
}

var natGatewayUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"FloatingIPs":  "floating_ips",
	"RegionLcuuid": "region",
}

var lbUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"Model":        "model",
	"VIP":          "vip",
	"RegionLcuuid": "region",
}

var lbListenerUpdatableStructFieldToDBField = map[string]string{
	"Name":     "name",
	"Protocol": "protocol",
	"Port":     "port",
	"IPs":      "ips",
	"SNATIPs":  "snat_ips",
}

var lbTargetServerUpdatableStructFieldToDBField = map[string]string{
	"IP":       "ip",
	"Port":     "port",
	"Protocol": "protocol",
}

var peerConnectionUpdatableStructFieldToDBField = map[string]string{
	"Name":               "name",
	"RemoteRegionLcuuid": "remote_region_lcuuid",
	"LocalRegionLcuuid":  "local_region_lcuuid",
}

var cenUpdatableStructFieldToDBField = map[string]string{
	"Name":       "name",
	"VPCLcuuids": "epc_ids",
}

var rdsInstanceUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"State":        "state",
	"Series":       "series",
	"Model":        "model",
}

var redisInstanceUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"State":        "state",
	"PublicHost":   "public_host",
}

var podClusterUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
	"ClusterName":  "cluster_name",
}

var podNodeUpdatableStructFieldToDBField = map[string]string{
	"State":        "state",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
	"VPCUNum":      "vcpu_num",
	"MemTotal":     "mem_total",
}

var podNamespaceUpdatableStructFieldToDBField = map[string]string{
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
}

var podIngressUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
}

var podServiceUpdatableStructFieldToDBField = map[string]string{
	"Name":             "name",
	"RegionLcuuid":     "region",
	"AZLcuuid":         "az",
	"Selector":         "selector",
	"PodIngressLcuuid": "pod_ingress_id",
	"ServiceClusterIP": "service_cluster_ip",
}

var podServicePortUpdatableStructFieldToDBField = map[string]string{
	"Name": "name",
}

var podGroupUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
	"PodNum":       "pod_num",
	"Label":        "label",
	"Type":         "type",
}

var podGroupPortUpdatableStructFieldToDBField = map[string]string{
	"Name": "name",
}

var podReplicaSetUpdatableStructFieldToDBField = map[string]string{
	"Name":         "name",
	"RegionLcuuid": "region",
	"AZLcuuid":     "az",
	"PodNum":       "pod_num",
}

var podUpdatableStructFieldToDBField = map[string]string{
	"Name":                "name",
	"RegionLcuuid":        "region",
	"AZLcuuid":            "az",
	"State":               "state",
	"VPCLcuuid":           "epc_id",
	"PodReplicaSetLcuuid": "pod_rs_id",
	"PodNodeLcuuid":       "pod_node_id",
	"CreatedAt":           "created_at",
}
