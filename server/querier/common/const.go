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

package common

const (
	SUCCESS                         = "SUCCESS"
	FAIL                            = "FAIL"
	INVALID_PARAMETERS              = "INVALID_PARAMETERS"
	RESOURCE_NOT_FOUND              = "RESOURCE_NOT_FOUND"
	RESOURCE_ALREADY_EXIST          = "RESOURCE_ALREADY_EXIST"
	PARAMETER_ILLEGAL               = "PARAMETER_ILLEGAL"
	INVALID_POST_DATA               = "INVALID_POST_DATA"
	SERVER_ERROR                    = "SERVER_ERROR"
	RESOURCE_NUM_EXCEEDED           = "RESOURCE_NUM_EXCEEDED"
	SELECTED_RESOURCES_NUM_EXCEEDED = "SELECTED_RESOURCES_NUM_EXCEEDED"
)

const (
	HOST_HOSTNAME     = "host_hostname"
	HOST_IP           = "host_ip"
	CHOST_HOSTNAME    = "chost_hostname"
	CHOST_IP          = "chost_ip"
	POD_NODE_HOSTNAME = "pod_node_hostname"
	POD_NODE_IP       = "pod_node_ip"
	BIZ_SERVICE_GROUP = "biz_service.group"

	TAP_PORT_HOST        = "tap_port_host"
	TAP_PORT_CHOST       = "tap_port_chost"
	TAP_PORT_POD_NODE    = "tap_port_pod_node"
	CAPTURE_NIC_HOST     = "capture_nic_host"
	CAPTURE_NIC_CHOST    = "capture_nic_chost"
	CAPTURE_NIC_POD_NODE = "capture_nic_pod_node"
)

const (
	HEADER_KEY_LANGUAGE = "X-Language"
	HEADER_KEY_X_ORG_ID = "X-Org-Id"
	DEFAULT_ORG_ID      = "1"
)

const NO_LIMIT = "-1"

var PEER_TABLES = []string{"l4_flow_log", "l7_flow_log", "application_map", "network_map", "vtap_flow_edge_port", "vtap_app_edge_port"}

var TRANS_MAP_ITEM_TAG = map[string]string{
	"k8s.label.":        "k8s_label",
	"k8s.annotation.":   "k8s_annotation",
	"k8s.env.":          "k8s_env",
	"cloud.tag.":        "cloud_tag",
	"os.app.":           "os_app",
	"biz_service.group": "biz_service_group",
}
