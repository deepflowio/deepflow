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

import (
	"github.com/goccy/go-json"
)

type Convertor struct{}

func (c Convertor) ToMapOmitEmpty(obj interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	b, _ := json.Marshal(obj)
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
	Convertor `json:"-"`

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	DomainLcuuids []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
}

func (r RegionFilterConditions) GetFilterConditions() map[string]interface{} {
	return r.ToMapOmitEmpty(r)
}

type RegionQueryFilterConditions struct {
	RegionFilterConditions
	Names         []string `schema:"name,omitempty" json:"NAME,omitempty"`
	DomainLcuuids []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
	RegionLcuuids []string `schema:"region,omitempty" json:"REGION,omitempty"`
	AnalyzerIPs   []string `schema:"analyzer_ip,omitempty" json:"ANALYZER_IP,omitempty"`
	ControllerIPs []string `schema:"controller_ip,omitempty" json:"CONTROLLER_IP,omitempty"`
}

type AZFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	DomainLcuuids []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
}

func (a AZFilterConditions) GetFilterConditions() map[string]interface{} {
	return a.ToMapOmitEmpty(a)
}

type AZQueryFilterConditions struct {
	AZFilterConditions
	UserIDParam
}

// VMFilterConditions directly applied to vm http response model.
type VMFilterConditions struct {
	Convertor `json:"-"`

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
	return v.ToMapOmitEmpty(v)
}

// VMQueryFilterConditions formed by http request query.
// User id filter conditions cannot be directly applied to the http response, and need to be converted into corresponding filter conditions
type VMQueryFilterConditions struct {
	VMFilterConditions
	UserIDParam
}

type HostFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	IPs     []string `schema:"ip,omitempty" json:"IP,omitempty"`
}

func (h HostFilterConditions) GetFilterConditions() map[string]interface{} {
	return h.ToMapOmitEmpty(h)
}

type HostQueryFilterConditions struct {
	HostFilterConditions
	UserIDParam // field is reserved but not supported actually.
}

type VInterfaceFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids     []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	DeviceIDs   []int    `schema:"device_id,omitempty" json:"DEVICE_ID,omitempty"`
	DeviceTypes []int    `schema:"device_type,omitempty" json:"DEVICE_TYPE,omitempty"`
	VPCIDs      []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (v VInterfaceFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

type VInterfaceQueryFilterConditions struct {
	VInterfaceFilterConditions
	UserIDParam
}
type SecurityGroupFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VMIDs   []int    `schema:"vm_id,omitempty" json:"VM_ID,omitempty"`
}

func (v SecurityGroupFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

type SecurityGroupQueryFilterConditions struct {
	SecurityGroupFilterConditions
	UserIDParam
}

type SecurityGroupRuleFilterConditions struct {
	Convertor `json:"-"`

	VMIDs []int `schema:"security_group_id,omitempty" json:"SG_ID,omitempty"`
}

func (v SecurityGroupRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

type SecurityGroupRuleQueryFilterConditions struct {
	SecurityGroupRuleFilterConditions
	UserIDParam
}

type NATGatewayFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (n NATGatewayFilterConditions) GetFilterConditions() map[string]interface{} {
	return n.ToMapOmitEmpty(n)
}

type NATGatewayQueryFilterConditions struct {
	NATGatewayFilterConditions
	UserIDParam
}

type NATRuleFilterConditions struct {
	Convertor `json:"-"`

	VPCIDs []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	NATIDs []int `schema:"nat_id,omitempty" json:"NAT_ID,omitempty"`
}

func (n NATRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return n.ToMapOmitEmpty(n)
}

type NATRuleQueryFilterConditions struct {
	NATRuleFilterConditions
	UserIDParam
}

type LBFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (l LBFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty(l)
}

type LBQueryFilterConditions struct {
	LBFilterConditions
	UserIDParam
}

type LBListenerFilterConditions struct {
	Convertor `json:"-"`

	VPCIDs []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (l LBListenerFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty(l)
}

type LBListenerQueryFilterConditions struct {
	LBListenerFilterConditions
	UserIDParam
}

type LBRuleFilterConditions struct {
	Convertor `json:"-"`

	VPCIDs              []int `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	LBIDs               []int `schema:"lb_id,omitempty" json:"LB_ID,omitempty"`
	LBListenerIDs       []int `schema:"lb_listener_id,omitempty" json:"LB_LISTENER_ID,omitempty"`
	LBTargetServerTypes []int `schema:"lb_target_server_type,omitempty" json:"LB_TARGET_SERVER_TYPE,omitempty"`
}

func (l LBRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return l.ToMapOmitEmpty(l)
}

type PeerConnectionFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type CENFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
}

type RDSInstanceFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type RDSInstanceQueryFilterConditions struct {
	RDSInstanceFilterConditions
	UserIDParam
}

type RedisInstanceFilterConditions struct {
	Convertor `json:"-"`

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

type RedisInstanceQueryFilterConditions struct {
	RedisInstanceFilterConditions
	UserIDParam
}

// net resource
// IPFilterConditions directly applied to pod http response model.
type IPFilterConditions struct {
	Convertor

	IP         []string `schema:"ip,omitempty" json:"IP,omitempty"`
	VPCIDs     []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	SubnetIDs  []int    `schema:"subnet_id,omitempty" json:"SUBNET_ID,omitempty"`
	IPTypes    []int    `schema:"ip_type,omitempty" json:"IP_TYPE,omitempty"`
	IPVersions []int    `schema:"ip_version,omitempty" json:"IP_VERSION,omitempty"`
	DeviceType []int    `schema:"device_type,omitempty" json:"DEVICE_TYPE,omitempty"`
	DeviceIDs  []int    `schema:"device_id,omitempty" json:"DEVICE_ID,omitempty"`
}

func (v IPFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// IPQueryFilterConditions formed by http request query.
type IPQueryFilterConditions struct {
	IPFilterConditions
	UserIDParam
}

// DHCPPortFilterConditions directly applied to pod http response model.
type DHCPPortFilterConditions struct {
	Convertor

	Lcuuids []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs     []int    `schema:"id,omitempty" json:"ID,omitempty"`
	VPCIDs  []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (v DHCPPortFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// DHCPPortQueryFilterConditions formed by http request query.
type DHCPPortQueryFilterConditions struct {
	DHCPPortFilterConditions
	UserIDParam
}

// VRouterFilterConditions directly applied to pod http response model.
type VRouterFilterConditions struct {
	Convertor

	Lcuuids   []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs       []int    `schema:"id,omitempty" json:"ID,omitempty"`
	SubnetIDs []int    `schema:"subnet_id,omitempty" json:"SUBNET_ID,omitempty"`
	VPCIDs    []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
}

func (v VRouterFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// VRouterQueryFilterConditions formed by http request query.
type VRouterQueryFilterConditions struct {
	VRouterFilterConditions
	UserIDParam
}

// RoutingTableFilterConditions directly applied to pod http response model.
type RoutingTableFilterConditions struct {
	Convertor

	RouterIDs []int `schema:"router_id,omitempty" json:"ROUTER_ID,omitempty"`
}

func (v RoutingTableFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// RoutingTableQueryFilterConditions formed by http request query.
type RoutingTableQueryFilterConditions struct {
	RoutingTableFilterConditions
	UserIDParam
}

// NetworkFilterConditions directly applied to pod http response model.
type NetworkFilterConditions struct {
	Convertor

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	RouterIDs     []int    `schema:"router_id,omitempty" json:"ROUTER_ID,omitempty"`
	VPCIDs        []int    `schema:"epc_id,omitempty" json:"EPC_ID,omitempty"`
	IPVersions    []int    `schema:"ip_version,omitempty" json:"IP_VERSION,omitempty"`
	RegionLcuuids []string `schema:"region,omitempty" json:"REGION,omitempty"`
	Domain        []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
	ISP           []int    `schema:"isp,omitempty" json:"ISP,omitempty"`
}

func (v NetworkFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// NetworkQueryFilterConditions formed by http request query.
type NetworkQueryFilterConditions struct {
	NetworkFilterConditions
	UserIDParam
}

// VPCFilterConditions directly applied to pod http response model.
type VPCFilterConditions struct {
	Convertor

	Lcuuids       []string `schema:"lcuuid,omitempty" json:"LCUUID,omitempty"`
	IDs           []int    `schema:"id,omitempty" json:"ID,omitempty"`
	RegionLcuuids []string `schema:"region,omitempty" json:"REGION,omitempty"`
	Domain        []string `schema:"domain,omitempty" json:"DOMAIN,omitempty"`
}

func (v VPCFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// VPCQueryFilterConditions formed by http request query.
type VPCQueryFilterConditions struct {
	VPCFilterConditions
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

func (p PodFilterConditions) GetFilterConditions() map[string]interface{} {
	return p.ToMapOmitEmpty(p)
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

func (v PodGroupQueryFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodGroupPortQueryFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodReplicaSetQueryFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodServiceFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodServicePortFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodIngressFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodIngressRuleFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodNodeFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodNamespaceFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
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

func (v PodClusterFilterConditions) GetFilterConditions() map[string]interface{} {
	return v.ToMapOmitEmpty(v)
}

// PodNodeQueryFilterConditions formed by http request query.
type PodClusterQueryFilterConditions struct {
	PodClusterFilterConditions
	UserIDParam
}
