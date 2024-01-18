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
	Name       string `gorm:"column:name;type:text;default:null" json:"NAME"`
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
	L3EPCID        int    `gorm:"primaryKey;column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
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
	L3EPCID        int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	L3EPCName      string `gorm:"column:l3_epc_name;type:varchar(256);default:null" json:"L3_EPC_NAME"`
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
	PodNSName      string `gorm:"column:pod_ns_name;type:varchar(256);default:null" json:"POD_NS_NAME"`
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
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	PodNodeID    int    `gorm:"column:pod_node_id;type:int;not null" json:"POD_NODE_ID"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodGroupID   int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
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
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodNamespace struct {
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
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

type ChPodK8sLabel struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodK8sLabels struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Labels  string `gorm:"column:labels;type:text;default:null" json:"LABELS"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodServiceK8sLabel struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodServiceK8sLabels struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Labels  string `gorm:"column:labels;type:text;default:null" json:"LABELS"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChStringEnum struct {
	TagName     string `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value       string `gorm:"primaryKey;column:value;type:varchar(256);default:null" json:"VALUE"`
	Name        string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Description string `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
}

type ChIntEnum struct {
	TagName     string `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value       int    `gorm:"primaryKey;column:value;type:int;default:0" json:"VALUE"`
	Name        string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Description string `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
}

type ChNodeType struct {
	ResourceType int    `gorm:"primaryKey;column:resource_type;type:int;not null" json:"RESOURCE_TYPE"`
	NodeType     string `gorm:"column:node_type;type:varchar(256);default:null" json:"NODE_TYPE"`
}

type ChChostCloudTag struct {
	ID    int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key   string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
}

type ChPodNSCloudTag struct {
	ID    int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key   string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
}

func (ChPodNSCloudTag) TableName() string {
	return "ch_pod_ns_cloud_tag"
}

type ChChostCloudTags struct {
	ID        int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	CloudTags string `gorm:"column:cloud_tags;type:text;default:null" json:"CLOUD_TAGS"`
}

type ChPodNSCloudTags struct {
	ID        int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	CloudTags string `gorm:"column:cloud_tags;type:text;default:null" json:"CLOUD_TAGS"`
}

func (ChPodNSCloudTags) TableName() string {
	return "ch_pod_ns_cloud_tags"
}

type ChOSAppTag struct {
	PID   int    `gorm:"primaryKey;column:pid;type:int;not null" json:"PID"`
	Key   string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
}

func (ChOSAppTag) TableName() string {
	return "ch_os_app_tag"
}

type ChOSAppTags struct {
	PID       int    `gorm:"primaryKey;column:pid;type:int;not null" json:"PID"`
	OSAPPTags string `gorm:"column:os_app_tags;type:text;default:null" json:"OS_APP_TAGS"`
}

func (ChOSAppTags) TableName() string {
	return "ch_os_app_tags"
}

type ChGProcess struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name    string `gorm:"column:name;type:text;default:null" json:"NAME"`
	IconID  int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	CHostID int    `gorm:"column:chost_id;type:int;not null" json:"CHOST_ID"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int" json:"L3_EPC_ID"`
}

func (ChGProcess) TableName() string {
	return "ch_gprocess"
}

type ChPodK8sAnnotation struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodK8sAnnotations struct {
	ID          int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Annotations string `gorm:"column:annotations;type:text;default:null" json:"ANNOTATIONS"`
	L3EPCID     int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID     int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodServiceK8sAnnotation struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodServiceK8sAnnotations struct {
	ID          int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Annotations string `gorm:"column:annotations;type:text;default:null" json:"ANNOTATIONS"`
	L3EPCID     int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID     int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodK8sEnv struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key     string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value   string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPodK8sEnvs struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Envs    string `gorm:"column:envs;type:text;default:null" json:"ENVS"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
}

type ChPrometheusLabelName struct {
	ID   int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
}

type ChPrometheusMetricName struct {
	ID   int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
}

type ChPrometheusMetricAPPLabelLayout struct {
	ID                  int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MetricName          string `gorm:"column:metric_name;type:varchar(256);not null" json:"METRIC_NAME"`
	APPLabelName        string `gorm:"column:app_label_name;type:varchar(256);not null" json:"APP_LABEL_NAME"`
	APPLabelColumnIndex uint8  `gorm:"column:app_label_column_index;type:int unsigned;not null" json:"APP_LABEL_COLUMN_INDEX"`
}

type ChAPPLabel struct {
	LabelNameID  int    `gorm:"primaryKey;column:label_name_id;type:int;not null" json:"LABEL_NAME_ID"`
	LabelValueID int    `gorm:"primaryKey;column:label_value_id;type:int unsigned;not null" json:"LABEL_VALUE_ID"`
	LabelValue   string `gorm:"column:label_value;type:text;not null" json:"LABEL_VALUE"`
}

func (ChAPPLabel) TableName() string {
	return "ch_app_label"
}

type ChTargetLabel struct {
	MetricID    int    `gorm:"primaryKey;column:metric_id;type:int;not null" json:"METRIC_ID"`
	LabelNameID int    `gorm:"primaryKey;column:label_name_id;type:int;not null" json:"LABEL_NAME_ID"`
	TargetID    int    `gorm:"primaryKey;column:target_id;type:int unsigned;not null" json:"TARGET_ID"`
	LabelValue  string `gorm:"column:label_value;type:varchar(256);not null" json:"LABEL_VALUE"`
}

type ChPrometheusTargetLabelLayout struct {
	TargetID          int    `gorm:"primaryKey;column:target_id;type:int;not null" json:"TARGET_ID"`
	TargetLabelNames  string `gorm:"column:target_label_names;type:text;not null" json:"TARGET_LABEL_NAMES"`
	TargetLabelValues string `gorm:"column:target_label_values;type:text;not null" json:"TARGET_LABEL_VALUES"`
}
type ChPodService struct {
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256)" json:"NAME"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int" json:"POD_NS_ID"`
}

type ChChost struct {
	ID      int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name    string `gorm:"column:name;type:varchar(256)" json:"NAME"`
	L3EPCID int    `gorm:"column:l3_epc_id;type:int" json:"L3_EPC_ID"`
	HostID  int    `gorm:"column:host_id;type:int" json:"HOST_ID"`
}
