/**
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
	SUCCESS                         = "SUCCESS"
	FAIL                            = "FAIL"
	CONFIG_PENDING                  = "CONFIG_PENDING"
	INVALID_PARAMETERS              = "INVALID_PARAMETERS"
	RESOURCE_NOT_FOUND              = "RESOURCE_NOT_FOUND"
	RESOURCE_ALREADY_EXIST          = "RESOURCE_ALREADY_EXIST"
	PARAMETER_ILLEGAL               = "PARAMETER_ILLEGAL"
	INVALID_POST_DATA               = "INVALID_POST_DATA"
	SERVER_ERROR                    = "SERVER_ERROR"
	RESOURCE_NUM_EXCEEDED           = "RESOURCE_NUM_EXCEEDED"
	SELECTED_RESOURCES_NUM_EXCEEDED = "SELECTED_RESOURCES_NUM_EXCEEDED"
	SERVICE_UNAVAILABLE             = "SERVICE_UNAVAILABLE"
	K8S_SET_VTAP_FAIL               = "K8S_SET_VTAP_FAIL"
)

const (
	PATH_REGION              = "/v2/regions/"
	PATH_AZ                  = "/v2/azs/"
	PATH_HOST                = "/v2/hosts/"
	PATH_VM                  = "/v2/vms/"
	PATH_VINTERFACE          = "/v2/vinterfaces/"
	PATH_NAT_GATEWAY         = "/v2/nat-gateways/"
	PATH_NAT_RULE            = "/v2/nat-rules/"
	PATH_SECURITY_GROUP      = "/v2/security-groups/"
	PATH_SECURITY_GROUP_RULE = "/v2/security-group-rules/"
	PATH_LB                  = "/v2/lbs/"
	PATH_LB_LISTENER         = "/v2/lb-listeners/"
	PATH_LB_RULE             = "/v2/lb-rules/"
	PATH_PEER_CONNECTION     = "/v2/peer-connections/"
	PATH_CEN                 = "/v2/cens/"
	PATH_POD                 = "/v2/pods/"
	PATH_POD_GROUP           = "/v2/pod-groups/"
	PATH_POD_GROUP_PORT      = "/v2/pod-group-ports/"
	PATH_POD_REPLICA_SET     = "/v2/pod-replica-sets/"
	PATH_POD_SERVICE         = "/v2/pod-services/"
	PATH_POD_SERVICE_PORT    = "/v2/pod-service-ports/"
	PATH_POD_INGRESS         = "/v2/pod-ingresses/"
	PATH_POD_INGRESS_RULE    = "/v2/pod-ingress-rules/"
	PATH_POD_NODE            = "/v2/pod-nodes/"
	PATH_POD_CLUSTER         = "/v2/pod-clusters/"
)

const (
	HEADER_KEY_X_USER_TYPE = "X-User-Type"
	HEADER_KEY_X_USER_ID   = "X-User-Id"
)
