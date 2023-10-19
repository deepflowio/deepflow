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

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
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
	ctrlrcommon.VIF_DEVICE_TYPE_HOST:           ctrlrcommon.RESOURCE_TYPE_HOST_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_VM:             ctrlrcommon.RESOURCE_TYPE_VM_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:        ctrlrcommon.RESOURCE_TYPE_VROUTER_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:      ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:    ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_LB:             ctrlrcommon.RESOURCE_TYPE_LB_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:   ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE: ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:       ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:    ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
	ctrlrcommon.VIF_DEVICE_TYPE_POD:            ctrlrcommon.RESOURCE_TYPE_POD_EN,
	ctrlrcommon.PROCESS_INSTANCE_TYPE:          ctrlrcommon.RESOURCE_TYPE_PROCESS_EN,
}
