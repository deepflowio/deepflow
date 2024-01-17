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
	CLOUD_SYNC_TIMER_DEFAULT = 60
	CLOUD_SYNC_TIMER_MIN     = 1
	CLOUD_SYNC_TIMER_MAX     = 86400
)

const (
	SECURITY_GROUP_RULE_ACCEPT  = 1
	SECURITY_GROUP_RULE_DROP    = 2
	SECURITY_GROUP_RULE_INGRESS = 1
	SECURITY_GROUP_RULE_EGRESS  = 2
	SECURITY_GROUP_IPV4         = 1
	SECURITY_GROUP_IPV6         = 2
)

const (
	PORT_RANGE_ALL = "0-65535"
	PROTOCOL_ALL   = "ALL"
)

const (
	SUBNET_DEFAULT_CIDR_IPV4 = "0.0.0.0/0"
	SUBNET_DEFAULT_CIDR_IPV6 = "::/0"
)

const (
	NAT_RULE_TYPE_DNAT = "DNAT"
	NAT_RULE_TYPE_SNAT = "SNAT"
)

const (
	LB_MODEL_INTERNAL = 1 + iota
	LB_MODEL_EXTERNAL
)

const (
	SVC_RULE_RESOURCE_NAME = "virtual-kubelet.io/provider-resource-name"
)
