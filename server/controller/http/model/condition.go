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

func (u UserIDParam) GetUserID() int {
	return u.UserID
}

type RegionFilterConditions struct {
	Convertor

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	DomainLcuuids []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
}

func (r RegionFilterConditions) GetFilterConditions() map[string]interface{} {
	return r.ToMapOmitEmpty()
}

type RegionQueryFilterConditions struct {
	RegionFilterConditions
	UserIDParam
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

func (v VMFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty()
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

type SecurityGroupFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VMIDs   []int    `schema:"vm_id,omitempty" json:"VM_ID,omitempty"`
}

type SecurityGroupRuleFilterConditions struct {
	Convertor

	VMIDs []int `schema:"security_group_id,omitempty" json:"SECURITY_GROUP_ID,omitempty"`
}

type NATGatewayFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (n NATGatewayFilterConditions) GetFilterConditions() map[string]interface{} {
	return n.ToMapOmitEmpty()
}

type NATGatewayQueryFilterConditions struct {
	NATGatewayFilterConditions
	UserIDParam
}

type NATRuleFilterConditions struct {
	Convertor

	VPCIDs []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	NATIDs []int `schema:"nat_id,omitempty" json:"NAT_ID,omitempty"`
}

func (n NATRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return n.ToMapOmitEmpty()
}

type LBFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (l LBFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty()
}

type LBQueryFilterConditions struct {
	LBFilterConditions
	UserIDParam
}

type LBListenerFilterConditions struct {
	Convertor

	VPCIDs []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (l LBListenerFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty()
}

type LBListenerQueryFilterConditions struct {
	LBListenerFilterConditions
	UserIDParam
}

type LBRuleFilterConditions struct {
	Convertor

	VPCIDs              []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	LBIDs               []int `schema:"lb_id,omitempty" json:"LB_ID,omitempty"`
	LBListenerIDs       []int `schema:"lb_listener_id,omitempty" json:"LB_LISTENER_ID,omitempty"`
	LBTargetServerTypes []int `schema:"lb_target_server_type,omitempty" json:"LB_TARGET_SERVER_TYPE,omitempty"`
}

func (l LBRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty()
}

type PeerConnectionFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type CENFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
}

type RDSInstanceFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type RDSInstanceQueryFilterConditions struct {
	RDSInstanceFilterConditions
	UserIDParam
}

type RedisInstanceFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type RedisInstanceQueryFilterConditions struct {
	RedisInstanceFilterConditions
	UserIDParam
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

func (v PodFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty()
}

// PodQueryFilterConditions formed by http request query.
type PodQueryFilterConditions struct {
	PodFilterConditions
	UserIDParam
}

// PodGroupFilterConditions directly applied to pod http response model.
type PodGroupFilterConditions struct {
	Convertor

	Lcuuids         []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs             []int    `schema:"id,omitempty" json:"ID,omitempty"`
	Names           []string `schema:"name,omitempty" json:"NAME,omitempty"`
	PodNamespaceIDs []int    `schema:"pod_namespace_id,omitempty" json:"POD_NAMESPACE_ID,omitempty"`
	VPCIDs          []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

// PodGroupQueryFilterConditions formed by http request query.
type PodGroupQueryFilterConditions struct {
	PodGroupFilterConditions
	UserIDParam
}

// PodGroupPortFilterConditions directly applied to pod http response model.
type PodGroupPortFilterConditions struct {
	Convertor

	PodServiceIDs []int `schema:"pod_service_id,omitempty" json:"POD_SERVICE_ID,omitempty"`
	PodGroupIDs   []int `schema:"pod_group_id,omitempty" json:"POD_GROUP_ID,omitempty"`
}

// PodGroupPortQueryFilterConditions formed by http request query.
type PodGroupPortQueryFilterConditions struct {
	PodGroupPortFilterConditions
}

// PodFilterPodReplicaSetFilterConditionsConditions directly applied to pod http response model.
type PodReplicaSetFilterConditions struct {
	Convertor

	Lcuuids         []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs             []int    `schema:"id,omitempty" json:"ID,omitempty"`
	PodNamespaceIDs []int    `schema:"pod_namespace_id,omitempty" json:"POD_NAMESPACE_ID,omitempty"`
	PodGroupIDs     []int    `schema:"pod_group_id,omitempty" json:"POD_GROUP_ID,omitempty"`
	VPCIDs          []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

// PodReplicaSetQueryFilterConditions formed by http request query.
type PodReplicaSetQueryFilterConditions struct {
	PodReplicaSetFilterConditions
	UserIDParam
}

// PodServiceFilterConditions directly applied to pod http response model.
type PodServiceFilterConditions struct {
	Convertor

	Lcuuids         []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs             []int    `schema:"id,omitempty" json:"ID,omitempty"`
	PodNamespaceIDs []int    `schema:"pod_namespace_id,omitempty" json:"POD_NAMESPACE_ID,omitempty"`
	PodIngressIDs   []int    `schema:"pod_ingress_id,omitempty" json:"POD_INGRESS_ID,omitempty"`
	VPCIDs          []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

// PodServiceQueryFilterConditions formed by http request query.
type PodServiceQueryFilterConditions struct {
	PodServiceFilterConditions
	UserIDParam
}

// PodServicePortFilterConditions directly applied to pod http response model.
type PodServicePortFilterConditions struct {
	Convertor

	PodServiceIDs []int `schema:"pod_service_id,omitempty" json:"POD_SERVICE_ID,omitempty"`
}

// PodServicePortQueryFilterConditions formed by http request query.
type PodServicePortQueryFilterConditions struct {
	PodServicePortFilterConditions
	UserIDParam
}

// PodIngressFilterConditions directly applied to pod http response model.
type PodIngressFilterConditions struct {
	Convertor

	Lcuuids         []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs             []int    `schema:"id,omitempty" json:"ID,omitempty"`
	PodNamespaceIDs []int    `schema:"pod_namespace_id,omitempty" json:"POD_NAMESPACE_ID,omitempty"`
	VPCIDs          []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

// PodIngressQueryFilterConditions formed by http request query.
type PodIngressQueryFilterConditions struct {
	PodIngressFilterConditions
	UserIDParam
}

// PodIngressRuleFilterConditions directly applied to pod http response model.
type PodIngressRuleFilterConditions struct {
	Convertor

	PodIngressIDs     []int `schema:"pod_ingress_id,omitempty" json:"POD_INGRESS_ID,omitempty"`
	PodServiceIDs     []int `schema:"pod_service_id,omitempty" json:"POD_SERVICE_ID,omitempty"`
	PortPodServiceIDs []int `schema:"port_pod_service_id,omitempty" json:"PORT_POD_SERVICE_ID,omitempty"` // 实际含义同 pod_service_id，为全景图提供方便
	Ports             []int `schema:"port,omitempty" json:"PORT,omitempty"`
}

// PodIngressRuleQueryFilterConditions formed by http request query.
type PodIngressRuleQueryFilterConditions struct {
	PodIngressRuleFilterConditions
	UserIDParam
}

// PodFilterConditions directly applied to pod http response model.
type PodNodeFilterConditions struct {
	Convertor

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	IPs           []string `schema:"ip,omitempty" json:"IP,omitempty"`
	PodClusterIDs []int    `schema:"pod_cluster_id,omitempty" json:"POD_CLUSTER_ID,omitempty"`
	VPCIDs        []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	RegionLcuuids []string `schema:"region,omitempty" json:"REGION,omitempty"`
	AZLcuuids     []string `schema:"az,omitempty" json:"AZ,omitempty"`
}

// PodNodeQueryFilterConditions formed by http request query.
type PodNodeQueryFilterConditions struct {
	PodNodeFilterConditions
	UserIDParam
}

// PodNamespaceFilterConditions directly applied to pod http response model.
type PodNamespaceFilterConditions struct {
	Convertor

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	PodClusterIDs []int    `schema:"pod_cluster_id,omitempty" json:"POD_CLUSTER_ID,omitempty"`
	VPCIDs        []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

// PodNamespaceQueryFilterConditions formed by http request query.
type PodNamespaceQueryFilterConditions struct {
	PodNamespaceFilterConditions
	UserIDParam
}

// PodClusterFilterConditions directly applied to pod http response model.
type PodClusterFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	Names   []string `schema:"name,omitempty" json:"NAME,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	Domain  []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
}

// PodNodeQueryFilterConditions formed by http request query.
type PodClusterQueryFilterConditions struct {
	PodClusterFilterConditions
	UserIDParam
}
