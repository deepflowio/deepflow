/*
 * Copyright (c) 2022 Yunshan Networks
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

package mysql

type ChRegion struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChAZ struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChVPC struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UID    string `gorm:"column:uid;type:char(64);default:null" json:"UID"`
}

func (ChVPC) TableName() string {
	return "ch_l3_epc"
}

type ChDevice struct {
	DeviceType int    `gorm:"primaryKey;column:devicetype;type:int;not null" json:"DEVICETYPE"`
	DeviceID   int    `gorm:"primaryKey;column:deviceid;type:int;not null" json:"DEVICEID"`
	Name       string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID     int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UID        string `gorm:"column:uid;type:char(64);default:null" json:"UID"`
}

type ChVTapPort struct {
	VTapID     int    `gorm:"primaryKey;column:vtap_id;type:int;not null" json:"VTAP_ID"`
	TapPort    int64  `gorm:"primaryKey;column:tap_port;type:bigint;not null" json:"TAP_PORT"`
	MacType    int    `gorm:"column:mac_type;type:int;default:null" json:"MAC_TYPE"`
	HostID     int    `gorm:"column:host_id;type:int;default:null" json:"HOST_ID"`
	Name       string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	HostName   string `gorm:"column:host_name;type:varchar(256);default:null" json:"HOST_NAME"`
	DeviceType int    `gorm:"column:device_type;type:int;not null" json:"DEVICE_TYPE"`
	DeviceID   int    `gorm:"column:device_id;type:int;not null" json:"DEVICE_ID"`
	DeviceName string `gorm:"column:device_name;type:varchar(256);not null" json:"DEVICE_NAME"`
	IconID     int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

func (ChVTapPort) TableName() string {
	return "ch_vtap_port"
}

type ChPodNodePort struct {
	ID                 int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Protocol           int    `gorm:"primaryKey;column:protocol;type:int;not null" json:"PROTOCOL"`
	Port               int    `gorm:"primaryKey;column:port;type:int;not null" json:"PORT"`
	PortLBID           int    `gorm:"column:port_lb_id;type:int;default:null" json:"PORT_LB_ID"`
	PortLBName         string `gorm:"column:port_lb_name;type:varchar(256);default:null" json:"PORT_LB_NAME"`
	PortLBListenerID   int    `gorm:"column:port_lb_listener_id;type:int;default:null" json:"PORT_LB_LISTENER_ID"`
	PortLBListenerName string `gorm:"column:port_lb_listener_name;type:varchar(256);default:null" json:"PORT_LB_LISTENER_NAME"`
	PortPodServiceID   int    `gorm:"column:port_pod_service_id;type:int;default:null" json:"PORT_POD_SERVICE_ID"`
	PortPodServiceName string `gorm:"column:port_pod_service_name;type:varchar(256);default:null" json:"PORT_POD_SERVICE_NAME"`
}

type ChPodPort struct {
	ID                 int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Protocol           int    `gorm:"primaryKey;column:protocol;type:int;not null" json:"PROTOCOL"`
	Port               int    `gorm:"primaryKey;column:port;type:int;not null" json:"PORT"`
	PortLBID           int    `gorm:"column:port_lb_id;type:int;default:null" json:"PORT_LB_ID"`
	PortLBName         string `gorm:"column:port_lb_name;type:varchar(256);default:null" json:"PORT_LB_NAME"`
	PortLBListenerID   int    `gorm:"column:port_lb_listener_id;type:int;default:null" json:"PORT_LB_LISTENER_ID"`
	PortLBListenerName string `gorm:"column:port_lb_listener_name;type:varchar(256);default:null" json:"PORT_LB_LISTENER_NAME"`
	PortPodServiceID   int    `gorm:"column:port_pod_service_id;type:int;default:null" json:"PORT_POD_SERVICE_ID"`
	PortPodServiceName string `gorm:"column:port_pod_service_name;type:varchar(256);default:null" json:"PORT_POD_SERVICE_NAME"`
}

type ChPodGroupPort struct {
	ID                 int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Protocol           int    `gorm:"primaryKey;column:protocol;type:int;not null" json:"PROTOCOL"`
	Port               int    `gorm:"primaryKey;column:port;type:int;not null" json:"PORT"`
	PortLBID           int    `gorm:"column:port_lb_id;type:int;default:null" json:"PORT_LB_ID"`
	PortLBName         string `gorm:"column:port_lb_name;type:varchar(256);default:null" json:"PORT_LB_NAME"`
	PortLBListenerID   int    `gorm:"column:port_lb_listener_id;type:int;default:null" json:"PORT_LB_LISTENER_ID"`
	PortLBListenerName string `gorm:"column:port_lb_listener_name;type:varchar(256);default:null" json:"PORT_LB_LISTENER_NAME"`
	PortPodServiceID   int    `gorm:"column:port_pod_service_id;type:int;default:null" json:"PORT_POD_SERVICE_ID"`
	PortPodServiceName string `gorm:"column:port_pod_service_name;type:varchar(256);default:null" json:"PORT_POD_SERVICE_NAME"`
}

type ChDevicePort struct {
	DeviceType         int    `gorm:"primaryKey;column:devicetype;type:int;not null" json:"DEVICETYPE"`
	DeviceID           int    `gorm:"primaryKey;column:deviceid;type:int;not null" json:"DEVICEID"`
	Protocol           int    `gorm:"primaryKey;column:protocol;type:int;not null" json:"PROTOCOL"`
	Port               int    `gorm:"primaryKey;column:port;type:int;not null" json:"PORT"`
	PortLBID           int    `gorm:"column:port_lb_id;type:int;default:null" json:"PORT_LB_ID"`
	PortLBName         string `gorm:"column:port_lb_name;type:varchar(256);default:null" json:"PORT_LB_NAME"`
	PortLBListenerID   int    `gorm:"column:port_lb_listener_id;type:int;default:null" json:"PORT_LB_LISTENER_ID"`
	PortLBListenerName string `gorm:"column:port_lb_listener_name;type:varchar(256);default:null" json:"PORT_LB_LISTENER_NAME"`
	PortPodServiceID   int    `gorm:"column:port_pod_service_id;type:int;default:null" json:"PORT_POD_SERVICE_ID"`
	PortPodServiceName string `gorm:"column:port_pod_service_name;type:varchar(256);default:null" json:"PORT_POD_SERVICE_NAME"`
}

type ChIPPort struct {
	IP                 string `gorm:"primaryKey;column:ip;type:varchar(64);not null" json:"IP"`
	SubnetID           int    `gorm:"primaryKey;column:subnet_id;type:int;not null" json:"SUBNET_ID"`
	Protocol           int    `gorm:"primaryKey;column:protocol;type:int;not null" json:"PROTOCOL"`
	Port               int    `gorm:"primaryKey;column:port;type:int;not null" json:"PORT"`
	PortLBID           int    `gorm:"column:port_lb_id;type:int;default:null" json:"PORT_LB_ID"`
	PortLBName         string `gorm:"column:port_lb_name;type:varchar(256);default:null" json:"PORT_LB_NAME"`
	PortLBListenerID   int    `gorm:"column:port_lb_listener_id;type:int;default:null" json:"PORT_LB_LISTENER_ID"`
	PortLBListenerName string `gorm:"column:port_lb_listener_name;type:varchar(256);default:null" json:"PORT_LB_LISTENER_NAME"`
	PortPodServiceID   int    `gorm:"column:port_pod_service_id;type:int;default:null" json:"PORT_POD_SERVICE_ID"`
	PortPodServiceName string `gorm:"column:port_pod_service_name;type:varchar(256);default:null" json:"PORT_POD_SERVICE_NAME"`
}

type ChServerPort struct {
	ServerPort     int    `gorm:"primaryKey;column:server_port;type:int;not null" json:"SERVER_PORT"`
	ServerPortName string `gorm:"column:server_port_name;type:varchar(256)" json:"SERVER_PORT_NAME"`
}

type ChIPRelation struct {
	VPCID          int    `gorm:"primaryKey;column:l3_epc_id;type:int;not null" json:"VPC_ID"`
	IP             string `gorm:"primaryKey;column:ip;type:varchar(64);not null" json:"IP"`
	NATGWID        int    `gorm:"column:natgw_id;type:int;default:null" json:"NATGW_ID"`
	NATGWName      string `gorm:"column:natgw_name;type:varchar(256);default:null" json:"NATGW_NAME"`
	LBID           int    `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	LBName         string `gorm:"column:lb_name;type:varchar(256);default:null" json:"LB_NAME"`
	LBListenerID   int    `gorm:"column:lb_listener_id;type:int;default:null" json:"LB_LISTENER_ID"`
	LBListenerName string `gorm:"column:lb_listener_name;type:varchar(256);default:null" json:"LB_LISTENER_NAME"`
	PodIngressID   int    `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	PodIngressName string `gorm:"column:pod_ingress_name;type:varchar(256);default:null" json:"POD_INGRESS_NAME"`
	PodServiceID   int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodServiceName string `gorm:"column:pod_service_name;type:varchar(256);default:null" json:"POD_SERVICE_NAME"`
}

func (ChIPRelation) TableName() string {
	return "ch_ip_relation"
}

type ChIPResource struct {
	IP             string `gorm:"primaryKey;column:ip;type:varchar(64);not null" json:"IP"`
	SubnetID       int    `gorm:"primaryKey;column:subnet_id;type:int;not null" json:"SUBNET_ID"`
	SubnetName     string `gorm:"column:subnet_name;type:varchar(256);default:null" json:"SUBNET_NAME"`
	RegionID       int    `gorm:"column:region_id;type:int;not null" json:"REGION_ID"`
	RegionName     string `gorm:"column:region_name;type:varchar(256);default:null" json:"REGION_NAME"`
	AZID           int    `gorm:"column:az_id;type:int;not null" json:"AZ_ID"`
	AZName         string `gorm:"column:az_name;type:varchar(256);default:null" json:"AZ_NAME"`
	HostID         int    `gorm:"column:host_id;type:int;not null" json:"HOST_ID"`
	HostName       string `gorm:"column:host_name;type:varchar(256);default:null" json:"HOST_NAME"`
	CHostID        int    `gorm:"column:chost_id;type:int;not null" json:"CHOST_ID"`
	CHostName      string `gorm:"column:chost_name;type:varchar(256);default:null" json:"CHOST_NAME"`
	VPCID          int    `gorm:"column:vpc_id;type:int;not null" json:"VPC_ID"`
	VPCName        string `gorm:"column:vpc_name;type:varchar(256);default:null" json:"VPC_NAME"`
	RouterID       int    `gorm:"column:router_id;type:int;not null" json:"ROUTER_ID"`
	RouterName     string `gorm:"column:router_name;type:varchar(256);default:null" json:"ROUTER_NAME"`
	DHCPGWID       int    `gorm:"column:dhcpgw_id;type:int;not null" json:"DHCPGW_ID"`
	DHCPGWName     string `gorm:"column:dhcpgw_name;type:varchar(256);default:null" json:"DHCPGW_NAME"`
	LBID           int    `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	LBName         string `gorm:"column:lb_name;type:varchar(256);default:null" json:"LB_NAME"`
	LBListenerID   int    `gorm:"column:lb_listener_id;type:int;default:null" json:"LB_LISTENER_ID"`
	LBListenerName string `gorm:"column:lb_listener_name;type:varchar(256);default:null" json:"LB_LISTENER_NAME"`
	NATGWID        int    `gorm:"column:natgw_id;type:int;default:null" json:"NATGW_ID"`
	NATGWName      string `gorm:"column:natgw_name;type:varchar(256);default:null" json:"NATGW_NAME"`
	RedisID        int    `gorm:"column:redis_id;type:int;not null" json:"REDIS_ID"`
	RedisName      string `gorm:"column:redis_name;type:varchar(256);default:null" json:"REDIS_NAME"`
	RDSID          int    `gorm:"column:rds_id;type:int;not null" json:"RDS_ID"`
	RDSName        string `gorm:"column:rds_name;type:varchar(256);default:null" json:"RDS_NAME"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodClusterName string `gorm:"column:pod_cluster_name;type:varchar(256);default:null" json:"POD_CLUSTER_NAME"`
	PodNSID        int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	PodNSName      string `gorm:"column:pod_ns_name;type:varchar(256);default:null" json:"pod_NS_NAME"`
	PodNodeID      int    `gorm:"column:pod_node_id;type:int;not null" json:"POD_NODE_ID"`
	PodNodeName    string `gorm:"column:pod_node_name;type:varchar(256);default:null" json:"POD_NODE_NAME"`
	PodIngressID   int    `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	PodIngressName string `gorm:"column:pod_ingress_name;type:varchar(256);default:null" json:"POD_INGRESS_NAME"`
	PodServiceID   int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodServiceName string `gorm:"column:pod_service_name;type:varchar(256);default:null" json:"POD_SERVICE_NAME"`
	PodGroupID     int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	PodGroupName   string `gorm:"column:pod_group_name;type:varchar(256);default:null" json:"POD_GROUP_NAME"`
	PodID          int    `gorm:"column:pod_id;type:int;default:null" json:"POD_ID"`
	PodName        string `gorm:"column:pod_name;type:varchar(256);default:null" json:"POD_NAME"`
	UID            string `gorm:"column:uid;type:char(64);default:null" json:"UID"`
}

func (ChIPResource) TableName() string {
	return "ch_ip_resource"
}

type ChNetwork struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

func (ChNetwork) TableName() string {
	return "ch_subnet"
}

type ChPod struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChPodCluster struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChPodGroup struct {
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	PodGroupType int    `gorm:"column:pod_group_type;type:int;default:null" json:"POD_GROUP_TYPE"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChPodNamespace struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

func (ChPodNamespace) TableName() string {
	return "ch_pod_ns"
}

type ChPodNode struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

type ChVTap struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	Type   int    `gorm:"column:type;type:int;not null" json:"TYPE"`
	IconID int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
}

func (ChVTap) TableName() string {
	return "ch_vtap"
}

type ChTapType struct {
	Value int    `gorm:"primaryKey;column:value;type:int;not null" json:"VALUE"`
	Name  string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
}

type ChLBListener struct {
	ID   int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
}

func (ChLBListener) TableName() string {
	return "ch_lb_listener"
}

type ChPodIngress struct {
	ID   int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
}

type ChK8sLabel struct {
	PodID   int    `gorm:"primaryKey;column:pod_id;type:int;not null" json:"POD_ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(64);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(64);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChK8sLabels struct {
	PodID   int    `gorm:"primaryKey;column:pod_id;type:int;not null" json:"POD_ID"`
	Labels  string `gorm:"column:labels;type:text;default:null" json:"LABELS"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChStringEnum struct {
	TagName string `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value   string `gorm:"primaryKey;column:value;type:varchar(256);default:null" json:"VALUE"`
	Name    string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
}

type ChIntEnum struct {
	TagName string `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value   int    `gorm:"primaryKey;column:value;type:int;default:0" json:"VALUE"`
	Name    string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
}

type ChNodeType struct {
	ResourceType int    `gorm:"primaryKey;column:resource_type;type:int;not null" json:"RESOURCE_TYPE"`
	NodeType     string `gorm:"column:node_type;type:varchar(256);default:null" json:"NODE_TYPE"`
}
