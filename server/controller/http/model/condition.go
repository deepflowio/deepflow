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

package model

import "encoding/json"

type Convertor struct{}

func (c *Convertor) ToMapOmitEmpty() map[string]interface{} {
	m := make(map[string]interface{})
	b, _ := json.Marshal(c)
	json.Unmarshal(b, &m)
	return m
}

type UserIDParam struct {
	UserID int `schema:"user_id,omitempty"`
}

// VMFilterConditions directly applied to vm http response model.
type VMFilterConditions struct {
	Convertor

	Lcuuids          []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs              []int    `schema:"id,omitempty" json:"ID,omitempty"`
	Names            []string `schema:"name,omitempty" json:"NAME,omitempty"`
	RegionLcuuids    []string `schema:"region,omitempty" json:"REGION,omitempty"`
	AZLcuuids        []string `schema:"az,omitempty" json:"AZ,omitempty"`
	VPCIDs           []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	LaunchServers    []string `schema:"launch_server,omitempty" json:"LAUNCH_SERVER,omitempty"`
	HostIDs          []int    `schema:"host_id,omitempty" json:"HOST_ID,omitempty"`
	SubnetIDs        []int    `schema:"subnet_id,omitempty" json:"SUBNET_ID,omitempty"`
	SecurityGroupIDs []int    `schema:"security_group_id,omitempty" json:"SECURITY_GROUP_ID,omitempty"`
}

// PodQueryFilterConditions formed by http request query.
// User id filter conditions cannot be directly applied to the http response, and need to be converted into corresponding filter conditions
type VMQueryFilterConditions struct {
	VMFilterConditions
	UserIDParam
}

type HostFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	IPs     []string `schema:"ip,omitempty" json:"IP,omitempty"`
}

type HostQueryFilterConditions struct {
	HostFilterConditions
}

// PodFilterConditions directly applied to pod http response model.
type PodFilterConditions struct {
	Convertor

	Lcuuids          []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs              []int    `schema:"id,omitempty" json:"ID,omitempty"`
	Names            []string `schema:"name,omitempty" json:"NAME,omitempty"`
	PodNamespaceIDs  []int    `schema:"pod_namespace_id,omitempty" json:"POD_NAMESPACE_ID,omitempty"`
	PodNodeIDs       []int    `schema:"pod_node_id,omitempty" json:"POD_NODE_ID,omitempty"`
	PodServiceIDs    []int    `schema:"pod_service_id,omitempty" json:"POD_SERVICE_ID,omitempty"`
	PodGroupIDs      []int    `schema:"pod_group_id,omitempty" json:"POD_GROUP_ID,omitempty"`
	PodReplicaSetIDs []int    `schema:"pod_rs_id,omitempty" json:"POD_RS_ID,omitempty"`
	VPCIDs           []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	SubnetIDs        []int    `schema:"subnet_id,omitempty" json:"SUBNET_ID,omitempty"`
	HostIDs          []int    `schema:"host_id,omitempty" json:"HOST_ID,omitempty"`
	RegionLcuuids    []string `schema:"region,omitempty" json:"REGION,omitempty"`
	AZLcuuids        []string `schema:"az,omitempty" json:"AZ,omitempty"`
}

// PodQueryFilterConditions formed by http request query.
type PodQueryFilterConditions struct {
	PodFilterConditions
	UserIDParam
}
