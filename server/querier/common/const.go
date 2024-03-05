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

	TAP_PORT_HOST        = "tap_port_host"
	TAP_PORT_CHOST       = "tap_port_chost"
	TAP_PORT_POD_NODE    = "tap_port_pod_node"
	CAPTURE_NIC_HOST     = "capture_nic_host"
	CAPTURE_NIC_CHOST    = "capture_nic_chost"
	CAPTURE_NIC_POD_NODE = "capture_nic_pod_node"
)
