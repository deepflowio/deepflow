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

package model

import (
	"time"
)

type Region struct {
	Lcuuid string `json:"lcuuid" binding:"required"`
	Label  string `json:"label"`
	Name   string `json:"name" binding:"required"`
}

type AZ struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Label        string `json:"label"`
	Name         string `json:"name" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type Host struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	IP           string `json:"ip" binding:"required"`
	Hostname     string `json:"hostname"`
	Type         int    `json:"type" binding:"required"`
	HType        int    `json:"htype" binding:"required"`
	VCPUNum      int    `json:"vcpu_num"`
	MemTotal     int    `json:"mem_total"`
	ExtraInfo    string `json:"extra_info"`
	AZLcuuid     string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type VM struct {
	Lcuuid        string            `json:"lcuuid" binding:"required"`
	Name          string            `json:"name" binding:"required"`
	Label         string            `json:"label"`
	IP            string            `json:"ip"`
	Hostname      string            `json:"hostname"`
	HType         int               `json:"htype" binding:"required"`
	State         int               `json:"state" binding:"required"`
	LaunchServer  string            `json:"launch_server" binding:"required"`
	CreatedAt     time.Time         `json:"created_at"`
	VPCLcuuid     string            `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid      string            `json:"az_lcuuid" binding:"required"`
	RegionLcuuid  string            `json:"region_lcuuid" binding:"required"`
	CloudTags     map[string]string `json:"cloud_tags"`
	NetworkLcuuid string            `json:"network_lcuuid"`
}

type VMPodNodeConnection struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	VMLcuuid        string `json:"vm_lcuuid" binding:"required"`
	PodNodeLcuuid   string `json:"pod_node_lcuuid" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid" binding:"required"`
}

type VPC struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label"`
	TunnelID     int    `json:"tunnel_id"`
	CIDR         string `json:"cidr"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type Network struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	Name            string `json:"name" binding:"required"`
	Label           string `json:"label"`
	SegmentationID  int    `json:"segmentation_id"`
	TunnelID        int    `json:"tunnel_id"`
	Shared          bool   `json:"shared"`
	External        bool   `json:"external"`
	IsVIP           bool   `json:"is_vip"`
	NetType         int    `json:"net_type" binding:"required"`
	VPCLcuuid       string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid        string `json:"az_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

type Subnet struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	Name            string `json:"name" binding:"required"`
	Label           string `json:"label"`
	CIDR            string `json:"cidr" binding:"required"`
	GatewayIP       string `json:"gateway_ip"`
	NetworkLcuuid   string `json:"network_lcuuid" binding:"required"`
	VPCLcuuid       string `json:"vpc_lcuuid" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

type VRouter struct {
	Lcuuid         string `json:"lcuuid" binding:"required"`
	Name           string `json:"name" binding:"required"`
	Label          string `json:"label"`
	GWLaunchServer string `json:"gw_launch_server" binding:"required"`
	VPCLcuuid      string `json:"vpc_lcuuid" binding:"required"`
	RegionLcuuid   string `json:"region_lcuuid" binding:"required"`
}

type RoutingTable struct {
	Lcuuid        string `json:"lcuuid" binding:"required"`
	VRouterLcuuid string `json:"vrouter_lcuuid" binding:"required"`
	Destination   string `json:"destination" binding:"required"`
	NexthopType   string `json:"nexthop_type" binding:"required"`
	Nexthop       string `json:"nexthop" binding:"required"`
}

type ThirdPartyDevice struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label" binding:"required"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type DHCPPort struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid     string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type VInterface struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	Name            string `json:"name"`
	Type            int    `json:"type" binding:"required"`
	Mac             string `json:"mac" binding:"required"`
	TapMac          string `json:"tap_mac"`
	DeviceLcuuid    string `json:"device_lcuuid" binding:"required"`
	DeviceType      int    `json:"device_type" binding:"required"`
	NetworkLcuuid   string `json:"network_lcuuid"`
	VPCLcuuid       string `json:"vpc_lcuuid"` // TODO not used
	RegionLcuuid    string `json:"region_lcuuid" binding:"required"`
	NetnsID         uint32 `json:"netns_id"`
	VTapID          uint32 `json:"vtap_id" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
	VPCID           int    // TODO @zhengya remove
}

type IP struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	VInterfaceLcuuid string `json:"vinterface_lcuuid" binding:"required"`
	IP               string `json:"ip" binding:"required"`
	SubnetLcuuid     string `json:"subnet_lcuuid" binding:"required"`
	RegionLcuuid     string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid"`
}

type VIP struct {
	Lcuuid string `json:"lcuuid" binding:"required"`
	IP     string `json:"ip" binding:"required"`
	VTapID uint32 `json:"vtap_id" binding:"required"`
}

type FloatingIP struct {
	Lcuuid        string `json:"lcuuid" binding:"required"`
	IP            string `json:"ip" binding:"required"`
	VMLcuuid      string `json:"vm_lcuuid"`
	NetworkLcuuid string `json:"network_lcuuid" binding:"required"`
	VPCLcuuid     string `json:"vpc_lcuuid" binding:"required"`
	RegionLcuuid  string `json:"region_lcuuid" binding:"required"`
}

type LB struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label"`
	Model        int    `json:"model" binding:"required"`
	VIP          string `json:"vip"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type LBListener struct {
	Lcuuid   string `json:"lcuuid" binding:"required"`
	LBLcuuid string `json:"lb_lcuuid" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Label    string `json:"label"`
	IPs      string `json:"ips" binding:"required"`
	SNATIPs  string `json:"snat_ips"`
	Protocol string `json:"protocol" binding:"required"`
	Port     int    `json:"port" binding:"required"`
}

type LBTargetServer struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	LBLcuuid         string `json:"lb_lcuuid" binding:"required"`
	LBListenerLcuuid string `json:"lb_listener_lcuuid" binding:"required"`
	Type             int    `json:"type" binding:"required"`
	IP               string `json:"ip"`
	VMLcuuid         string `json:"vm_lcuuid"`
	Protocol         string `json:"protocol" binding:"required"`
	Port             int    `json:"port" binding:"required"`
	VPCLcuuid        string `json:"vpc_lcuuid" binding:"required"`
}

type LBVMConnection struct {
	Lcuuid   string `json:"lcuuid" binding:"required"`
	LBLcuuid string `json:"lb_lcuuid" binding:"required"`
	VMLcuuid string `json:"vm_lcuuid" binding:"required"`
}

type NATGateway struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label" binding:"required"`
	FloatingIPs  string `json:"floating_ips"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type NATRule struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	NATGatewayLcuuid string `json:"nat_lcuuid" binding:"required"`
	Type             string `json:"type" binding:"required"`
	Protocol         string `json:"protocol" binding:"required"`
	FloatingIP       string `json:"floating_ip" binding:"required"`
	FloatingIPPort   int    `json:"floating_ip_port"`
	FixedIP          string `json:"fixed_ip" binding:"required"`
	FixedIPPort      int    `json:"fixed_ip_port"`
	VInterfaceLcuuid string `json:"vinterface_lcuuid"`
}

type NATVMConnection struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	NATGatewayLcuuid string `json:"nat_gateway_lcuuid" binding:"required"`
	VMLcuuid         string `json:"vm_lcuuid" binding:"required"`
}

type PeerConnection struct {
	Lcuuid             string `json:"lcuuid" binding:"required"`
	Name               string `json:"name" binding:"required"`
	Label              string `json:"label"`
	LocalVPCLcuuid     string `json:"local_epc_lcuuid" binding:"required"`
	RemoteVPCLcuuid    string `json:"remote_epc_lcuuid" binding:"required"`
	LocalRegionLcuuid  string `json:"local_region_lcuuid" binding:"required"`
	RemoteRegionLcuuid string `json:"remote_region_lcuuid" binding:"required"`
}

type CEN struct {
	Lcuuid     string   `json:"lcuuid" binding:"required"`
	Name       string   `json:"name" binding:"required"`
	Label      string   `json:"label"`
	VPCLcuuids []string `json:"vpc_lcuuids"`
}

type RedisInstance struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label"`
	State        int    `json:"state"`
	Version      string `json:"version" binding:"required"`
	InternalHost string `json:"internal_host"`
	PublicHost   string `json:"public_host"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid     string `json:"az_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type RDSInstance struct {
	Lcuuid       string `json:"lcuuid" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Label        string `json:"label"`
	State        int    `json:"state"`
	Type         int    `json:"type" binding:"required"`
	Version      string `json:"version" binding:"required"`
	Series       int    `json:"series"`
	Model        int    `json:"model"`
	VPCLcuuid    string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid     string `json:"az_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid" binding:"required"`
}

type SubDomain struct {
	TeamID        int    `json:"team_id" binding:"required"`
	Lcuuid        string `json:"lcuuid" binding:"required"`
	Name          string `json:"name" binding:"required"`
	DisplayName   string `json:"display_name" binding:"required"`
	ClusterID     string `json:"cluster_id" binding:"required"`
	VpcUUID       string `json:"vpc_uuid" binding:"required"`
	PortNameRegex string `json:"port_name_regex"`
	Config        string `json:"config" binding:"required"`
}

type PodCluster struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	Name            string `json:"name" binding:"required"`
	ClusterName     string `json:"cluster_name" binding:"required"`
	Version         string `json:"version" binding:"required"`
	VPCLcuuid       string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid        string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid    string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid" binding:"required"`
}

type PodNode struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	Name             string `json:"name" binding:"required"`
	Type             int    `json:"type" binding:"required"`
	ServerType       int    `json:"server_type" binding:"required"`
	State            int    `json:"state" binding:"required"`
	IP               string `json:"ip" binding:"required"`
	Hostname         string `json:"hostname"`
	VCPUNum          int    `json:"vcpu_num"`
	MemTotal         int    `json:"memory_total"`
	PodClusterLcuuid string `json:"pod_cluster_lcuuid" binding:"required"`
	VPCLcuuid        string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid         string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid     string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid" binding:"required"`
}

type PodNamespace struct {
	Lcuuid           string            `json:"lcuuid" binding:"required"`
	Name             string            `json:"name" binding:"required"`
	PodClusterLcuuid string            `json:"pod_cluster_lcuuid" binding:"required"`
	AZLcuuid         string            `json:"az_lcuuid" binding:"required"`
	RegionLcuuid     string            `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid  string            `json:"sub_domain_lcuuid" binding:"required"`
	CloudTags        map[string]string `json:"cloud_tags"`
}

type PodService struct {
	Lcuuid             string `json:"lcuuid" binding:"required"`
	Name               string `json:"name" binding:"required"`
	Metadata           string `json:"-"`
	MetadataHash       string `json:"metadata_hash"`
	Spec               string `json:"-"`
	SpecHash           string `json:"spec_hash"`
	Label              string `json:"label"`
	Annotation         string `json:"annotation"`
	Type               int    `json:"type" binding:"required"`
	Selector           string `json:"selector"`
	ExternalIP         string `json:"external_ip"`
	ServiceClusterIP   string `json:"service_cluster_ip"`
	PodIngressLcuuid   string `json:"pod_ingress_lcuuid"`
	PodNamespaceLcuuid string `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid   string `json:"pod_cluster_lcuuid" binding:"required"`
	VPCLcuuid          string `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid           string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid       string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid    string `json:"sub_domain_lcuuid" binding:"required"`
}

func (p PodService) ToLoggable() interface{} {
	return PodService{
		Lcuuid:             p.Lcuuid,
		Name:               p.Name,
		MetadataHash:       p.MetadataHash,
		SpecHash:           p.SpecHash,
		Label:              p.Label,
		Annotation:         p.Annotation,
		Type:               p.Type,
		Selector:           p.Selector,
		ExternalIP:         p.ExternalIP,
		ServiceClusterIP:   p.ServiceClusterIP,
		PodIngressLcuuid:   p.PodIngressLcuuid,
		PodNamespaceLcuuid: p.PodNamespaceLcuuid,
		PodClusterLcuuid:   p.PodClusterLcuuid,
		VPCLcuuid:          p.VPCLcuuid,
		AZLcuuid:           p.AZLcuuid,
		RegionLcuuid:       p.RegionLcuuid,
		SubDomainLcuuid:    p.SubDomainLcuuid,
	}
}

type PodServicePort struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	Name             string `json:"name" binding:"required"`
	Protocol         string `json:"protocol" binding:"required"`
	Port             int    `json:"port"`
	TargetPort       int    `json:"target_port"`
	NodePort         int    `json:"node_port"`
	PodServiceLcuuid string `json:"pod_service_lcuuid" binding:"required"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid" binding:"required"`
}

type PodGroup struct {
	Lcuuid             string `json:"lcuuid" binding:"required"`
	Name               string `json:"name" binding:"required"`
	Metadata           string `json:"-"`
	MetadataHash       string `json:"metadata_hash"`
	Spec               string `json:"-"`
	SpecHash           string `json:"spec_hash"`
	Label              string `json:"label"`
	Type               int    `json:"type" binding:"required"`
	PodNum             int    `json:"pod_num" binding:"required"`
	PodNamespaceLcuuid string `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid   string `json:"pod_cluster_lcuuid" binding:"required"`
	AZLcuuid           string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid       string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid    string `json:"sub_domain_lcuuid" binding:"required"`
}

func (p PodGroup) ToLoggable() interface{} {
	return PodGroup{
		Lcuuid:             p.Lcuuid,
		Name:               p.Name,
		MetadataHash:       p.MetadataHash,
		SpecHash:           p.SpecHash,
		Label:              p.Label,
		Type:               p.Type,
		PodNum:             p.PodNum,
		PodNamespaceLcuuid: p.PodNamespaceLcuuid,
		PodClusterLcuuid:   p.PodClusterLcuuid,
		AZLcuuid:           p.AZLcuuid,
		RegionLcuuid:       p.RegionLcuuid,
		SubDomainLcuuid:    p.SubDomainLcuuid,
	}
}

type PodGroupPort struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	Name             string `json:"name" binding:"required"`
	Protocol         string `json:"protocol" binding:"required"`
	Port             int    `json:"port" binding:"required"`
	PodGroupLcuuid   string `json:"pod_group_lcuuid" binding:"required"`
	PodServiceLcuuid string `json:"pod_service_lcuuid" binding:"required"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid" binding:"required"`
}

type PodIngress struct {
	Lcuuid             string `json:"lcuuid" binding:"required"`
	Name               string `json:"name" binding:"required"`
	PodNamespaceLcuuid string `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid   string `json:"pod_cluster_lcuuid" binding:"required"`
	AZLcuuid           string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid       string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid    string `json:"sub_domain_lcuuid" binding:"required"`
}

type PodIngressRule struct {
	Lcuuid           string `json:"lcuuid" binding:"required"`
	Name             string `json:"name" binding:"required"`
	Protocol         string `json:"protocol" binding:"required"`
	Host             string `json:"host"`
	PodIngressLcuuid string `json:"pod_ingress_lcuuid" binding:"required"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid"`
}

type PodIngressRuleBackend struct {
	Lcuuid               string `json:"lcuuid" binding:"required"`
	Path                 string `json:"path"`
	Port                 int    `json:"port" binding:"required"`
	PodServiceLcuuid     string `json:"pod_service_lcuuid" binding:"required"`
	PodIngressRuleLcuuid string `json:"pod_ingress_rule_lcuuid" binding:"required"`
	PodIngressLcuuid     string `json:"pod_ingress_lcuuid" binding:"required"`
	SubDomainLcuuid      string `json:"sub_domain_lcuuid"`
}

type PodReplicaSet struct {
	Lcuuid             string `json:"lcuuid" binding:"required"`
	Name               string `json:"name" binding:"required"`
	Label              string `json:"label"`
	PodNum             int    `json:"pod_num" binding:"required"`
	PodGroupLcuuid     string `json:"pod_group_lcuuid" binding:"required"`
	PodNamespaceLcuuid string `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid   string `json:"pod_cluster_lcuuid" binding:"required"`
	AZLcuuid           string `json:"az_lcuuid" binding:"required"`
	RegionLcuuid       string `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid    string `json:"sub_domain_lcuuid" binding:"required"`
}

type Pod struct {
	Lcuuid              string    `json:"lcuuid" binding:"required"`
	Name                string    `json:"name" binding:"required"`
	Label               string    `json:"label"`
	ContainerIDs        string    `json:"container_ids"`
	Annotation          string    `json:"annotation"`
	ENV                 string    `json:"env"`
	State               int       `json:"state" binding:"required"`
	CreatedAt           time.Time `json:"created_at"`
	PodReplicaSetLcuuid string    `json:"pod_replica_set_lcuuid"`
	PodNodeLcuuid       string    `json:"pod_node_lcuuid" binding:"required"`
	PodGroupLcuuid      string    `json:"pod_group_lcuuid" binding:"required"`
	PodServiceLcuuid    string    `json:"pod_service_lcuuid" binding:"required"`
	PodNamespaceLcuuid  string    `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid    string    `json:"pod_cluster_lcuuid" binding:"required"`
	VPCLcuuid           string    `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid            string    `json:"az_lcuuid" binding:"required"`
	RegionLcuuid        string    `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid     string    `json:"sub_domain_lcuuid" binding:"required"`
}

type ConfigMap struct {
	Lcuuid             string    `json:"lcuuid" binding:"required"`
	Name               string    `json:"name" binding:"required"`
	Data               string    `json:"-"`
	DataHash           string    `json:"data_hash"`
	PodNamespaceLcuuid string    `json:"pod_namespace_lcuuid" binding:"required"`
	PodClusterLcuuid   string    `json:"pod_cluster_lcuuid" binding:"required"`
	VPCLcuuid          string    `json:"vpc_lcuuid" binding:"required"`
	AZLcuuid           string    `json:"az_lcuuid" binding:"required"`
	RegionLcuuid       string    `json:"region_lcuuid" binding:"required"`
	SubDomainLcuuid    string    `json:"sub_domain_lcuuid" binding:"required"`
	CreatedAt          time.Time `json:"created_at"`
}

func (c ConfigMap) ToLoggable() interface{} {
	return ConfigMap{
		Lcuuid:             c.Lcuuid,
		Name:               c.Name,
		DataHash:           c.DataHash,
		PodNamespaceLcuuid: c.PodNamespaceLcuuid,
		PodClusterLcuuid:   c.PodClusterLcuuid,
		VPCLcuuid:          c.VPCLcuuid,
		AZLcuuid:           c.AZLcuuid,
		RegionLcuuid:       c.RegionLcuuid,
		SubDomainLcuuid:    c.SubDomainLcuuid,
		CreatedAt:          c.CreatedAt,
	}
}

type PodGroupConfigMapConnection struct {
	Lcuuid          string `json:"lcuuid" binding:"required"`
	PodGroupLcuuid  string `json:"pod_group_lcuuid" binding:"required"`
	ConfigMapLcuuid string `json:"config_map_lcuuid" binding:"required"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid" binding:"required"`
}

type Process struct {
	Lcuuid          string    `json:"lcuuid" binding:"required"`
	Name            string    `json:"name"`
	VTapID          uint32    `json:"vtap_id" binding:"required"`
	PID             uint64    `json:"pid" binding:"required"`
	ProcessName     string    `json:"process_name" binding:"required"`
	CommandLine     string    `json:"command_line"`
	UserName        string    `json:"user_name"`
	StartTime       time.Time `json:"start_time" binding:"required"`
	OSAPPTags       string    `json:"os_app_tags"`
	NetnsID         uint32    `json:"netns_id"`
	ContainerID     string    `json:"container_id"`
	SubDomainLcuuid string    `json:"sub_domain_lcuuid"`
}

type SubDomainResource struct {
	Verified                     bool `json:"verified"`
	ErrorState                   int
	ErrorMessage                 string
	SyncAt                       time.Time
	Networks                     []Network
	Subnets                      []Subnet
	VInterfaces                  []VInterface
	IPs                          []IP
	PodClusters                  []PodCluster
	PodNodes                     []PodNode
	VMPodNodeConnections         []VMPodNodeConnection
	PodNamespaces                []PodNamespace
	PodIngresses                 []PodIngress
	PodIngressRules              []PodIngressRule
	PodIngressRuleBackends       []PodIngressRuleBackend
	PodServices                  []PodService
	PodServicePorts              []PodServicePort
	PodGroups                    []PodGroup
	PodGroupPorts                []PodGroupPort
	PodReplicaSets               []PodReplicaSet
	Pods                         []Pod
	ConfigMaps                   []ConfigMap
	PodGroupConfigMapConnections []PodGroupConfigMapConnection
	Processes                    []Process
}

type Resource struct {
	Verified                     bool
	ErrorState                   int
	ErrorMessage                 string
	SyncAt                       time.Time
	SubDomains                   []SubDomain
	Regions                      []Region
	AZs                          []AZ
	Hosts                        []Host
	VMs                          []VM
	VPCs                         []VPC
	Networks                     []Network
	Subnets                      []Subnet
	VRouters                     []VRouter
	RoutingTables                []RoutingTable
	DHCPPorts                    []DHCPPort
	NATGateways                  []NATGateway
	NATRules                     []NATRule
	NATVMConnections             []NATVMConnection
	LBs                          []LB
	LBListeners                  []LBListener
	LBTargetServers              []LBTargetServer
	LBVMConnections              []LBVMConnection
	PeerConnections              []PeerConnection
	CENs                         []CEN
	RedisInstances               []RedisInstance
	RDSInstances                 []RDSInstance
	ThirdPartyDevices            []ThirdPartyDevice
	VInterfaces                  []VInterface
	IPs                          []IP
	VIPs                         []VIP
	FloatingIPs                  []FloatingIP
	PodClusters                  []PodCluster
	PodNodes                     []PodNode
	VMPodNodeConnections         []VMPodNodeConnection
	PodNamespaces                []PodNamespace
	PodGroups                    []PodGroup
	PodReplicaSets               []PodReplicaSet
	Pods                         []Pod
	PodServices                  []PodService
	PodServicePorts              []PodServicePort
	PodGroupPorts                []PodGroupPort
	PodIngresses                 []PodIngress
	PodIngressRules              []PodIngressRule
	PodIngressRuleBackends       []PodIngressRuleBackend
	ConfigMaps                   []ConfigMap
	PodGroupConfigMapConnections []PodGroupConfigMapConnection
	Processes                    []Process
	SubDomainResources           map[string]SubDomainResource
}

type AdditionalResource struct {
	AZs                   []AZ
	VPCs                  []VPC
	Subnets               []Network
	SubnetCIDRs           []Subnet
	Hosts                 []Host
	CHosts                []VM
	VInterfaces           []VInterface
	IPs                   []IP
	CHostCloudTags        UUIDToCloudTags
	PodNamespaceCloudTags UUIDToCloudTags
	LB                    []LB
	LBListeners           []LBListener
	LBTargetServers       []LBTargetServer
	PeerConnections       []PeerConnection
	SubDomainResources    map[string]*AdditionalSubdomainResource
}

type UUIDToCloudTags map[string]map[string]string

type AdditionalSubdomainResource struct {
	PodNamespaceCloudTags UUIDToCloudTags
}

type BasicInfo struct {
	OrgID     int       `json:"org_id"`
	TeamID    int       `json:"team_id"`
	Lcuuid    string    `json:"lcuuid"`
	Name      string    `json:"name"`
	Type      int       `json:"type"`
	Interval  int       `json:"interval"`
	CreatedAt time.Time `json:"created_at"`
}
