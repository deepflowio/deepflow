/*
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

package common

const (
	INVALID_POST_DATA = "INVALID_POST_DATA"
)

const (
	DATABASE_FLOW_LOG = "flow_log"
	TABLE_L7_FLOW_LOG = "l7_flow_log"
)

const (
	L7_FLOW_TYPE_REQUEST  = 0
	L7_FLOW_TYPE_RESPONSE = 1
	L7_FLOW_TYPE_SESSION  = 2
)

// tap_side
const (
	TAP_SIDE_UNKNOWN                   = ""
	TAP_SIDE_CLIENT_PROCESS            = "c-p"
	TAP_SIDE_CLIENT_NIC                = "c"
	TAP_SIDE_CLIENT_POD_NODE           = "c-nd"
	TAP_SIDE_CLIENT_HYPERVISOR         = "c-hv"
	TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR = "c-gw-hv"
	TAP_SIDE_CLIENT_GATEWAY            = "c-gw"
	TAP_SIDE_SERVER_GATEWAY            = "s-gw"
	TAP_SIDE_SERVER_GATEWAY_HAPERVISOR = "s-gw-hv"
	TAP_SIDE_SERVER_HYPERVISOR         = "s-hv"
	TAP_SIDE_SERVER_POD_NODE           = "s-nd"
	TAP_SIDE_SERVER_NIC                = "s"
	TAP_SIDE_SERVER_PROCESS            = "s-p"
	TAP_SIDE_REST                      = "rest"
	TAP_SIDE_LOCAL                     = "local"
	TAP_SIDE_APP                       = "app"
	TAP_SIDE_CLIENT_APP                = "c-app"
	TAP_SIDE_SERVER_APP                = "s-app"
)

var TAP_SIDE_RANKS = map[string]int{
	TAP_SIDE_CLIENT_PROCESS:            1,
	TAP_SIDE_CLIENT_NIC:                2,
	TAP_SIDE_CLIENT_POD_NODE:           3,
	TAP_SIDE_CLIENT_HYPERVISOR:         4,
	TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR: 5,
	TAP_SIDE_CLIENT_GATEWAY:            6,
	TAP_SIDE_SERVER_GATEWAY:            6, // 由于可能多次穿越网关区域，c-gw和s-gw还需要重排
	TAP_SIDE_SERVER_GATEWAY_HAPERVISOR: 8,
	TAP_SIDE_SERVER_HYPERVISOR:         9,
	TAP_SIDE_SERVER_POD_NODE:           10,
	TAP_SIDE_SERVER_NIC:                11,
	TAP_SIDE_SERVER_PROCESS:            12,
	TAP_SIDE_REST:                      13,
	TAP_SIDE_LOCAL:                     13, // rest和local需要就近排列到其他位置上
}
