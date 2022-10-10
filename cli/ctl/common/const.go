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

const (
	SUCCESS = "SUCCESS"
)

const (
	DEFAULT_ENCRYPTION_PASSWORD = "******"

	TENCENT_EN    = "tencent"
	AWS_EN        = "aws"
	ALIYUN_EN     = "aliyun"
	KUBERNETES_EN = "kubernetes"
	QINGCLOUD_EN  = "qingcloud"
	AGENT_SYNC_EN = "agent_sync"
	BAIDU_BCE_EN  = "baidu_bce"

	TENCENT    = 4
	AWS        = 6
	ALIYUN     = 9
	KUBERNETES = 11
	QINGCLOUD  = 14
	AGENT_SYNC = 23
	BAIDU_BCE  = 25
)

const (
	VTAP_STATE_NOT_CONNECTED = iota
	VTAP_STATE_NORMAL
	VTAP_STATE_DISABLE
	VTAP_STATE_PENDING
)

const (
	VTAP_STATE_NOT_CONNECTED_STR = "LOST"
	VTAP_STATE_NORMAL_STR        = "RUNNING"
	VTAP_STATE_DISABLE_STR       = "DISABLE"
	VTAP_STATE_PENDING_STR       = "PENDING"
)

var RESOURCE_TYPES = []string{
	"SubDomains", "Regions", "AZs", "Hosts", "VMs", "VPCs", "Networks", "Subnets", "VRouters",
	"RoutingTables", "DHCPPorts", "SecurityGroups", "SecurityGroupRules", "VMSecurityGroups",
	"NATGateways", "NATRules", "NATVMConnections", "LBs", "LBListeners", "LBTargetServers",
	"LBVMConnections", "PeerConnections", "CENs", "RedisInstances", "RDSInstances", "VInterfaces",
	"IPs", "FloatingIPs", "PodClusters", "PodNodes", "VMPodNodeConnections", "PodNamespaces",
	"PodGroups", "PodReplicaSets", "Pods", "PodServices", "PodServicePorts", "PodGroupPorts",
	"PodIngresses", "PodIngressRules", "PodIngressRuleBackends",
}

const (
	VTAP_TYPE_KVM = 1 + iota
	VTAP_TYPE_ESXI
	VTAP_TYPE_WORKLOAD_V
	_ // 4
	VTAP_TYPE_WORKLOAD_P
	VTAP_TYPE_DEDICATED
	VTAP_TYPE_POD_HOST
	VTAP_TYPE_POD_VM
	VTAP_TYPE_TUNNEL_DECAPSULATION
	VTAP_TYPE_HYPER_V
)

var VTapTypeName = map[int]string{
	VTAP_TYPE_KVM:                  "KVM",
	VTAP_TYPE_ESXI:                 "EXSI",
	VTAP_TYPE_WORKLOAD_V:           "CHOST_VM",
	VTAP_TYPE_WORKLOAD_P:           "CHOST_BM",
	VTAP_TYPE_DEDICATED:            "DEDICATED",
	VTAP_TYPE_POD_HOST:             "K8S_BM",
	VTAP_TYPE_POD_VM:               "K8S_VM",
	VTAP_TYPE_TUNNEL_DECAPSULATION: "TUN_DECAP",
	VTAP_TYPE_HYPER_V:              "HYPER_V",
}
