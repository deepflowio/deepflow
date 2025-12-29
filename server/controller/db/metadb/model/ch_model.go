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

type ChIDBase struct {
	ID int `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
}

func (b ChIDBase) GetID() int {
	return b.ID
}

type ChUpdatedAtBase struct {
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (b ChUpdatedAtBase) GetUpdatedAt() time.Time {
	return b.UpdatedAt
}

type ChRegion struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID    int       `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChAZ struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Name            string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
}

type ChVPC struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Name            string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UID             string `gorm:"column:uid;type:char(64);default:null" json:"UID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
}

func (ChVPC) TableName() string {
	return "ch_l3_epc"
}

type ChDevice struct {
	ChUpdatedAtBase `gorm:"embedded"`
	DeviceType      int    `gorm:"primaryKey;column:devicetype;type:int;not null" json:"DEVICETYPE"`
	DeviceID        int    `gorm:"primaryKey;column:deviceid;type:int;not null" json:"DEVICEID"`
	Name            string `gorm:"column:name;type:text;default:null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UID             string `gorm:"column:uid;type:char(64);default:null" json:"UID"`
	Hostname        string `gorm:"column:hostname;type:varchar(256)" json:"HOSTNAME"`
	IP              string `gorm:"column:ip;type:varchar(64)" json:"IP"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

func (c ChDevice) GetID() int {
	return c.DeviceID
}

type ChVTapPort struct {
	VTapID      int       `gorm:"primaryKey;column:vtap_id;type:int;not null" json:"VTAP_ID"`
	TapPort     int64     `gorm:"primaryKey;column:tap_port;type:bigint;not null" json:"TAP_PORT"`
	MacType     int       `gorm:"column:mac_type;type:int;default:null" json:"MAC_TYPE"`
	HostID      int       `gorm:"column:host_id;type:int;default:null" json:"HOST_ID"`
	Name        string    `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	HostName    string    `gorm:"column:host_name;type:varchar(256);default:null" json:"HOST_NAME"`
	DeviceType  int       `gorm:"column:device_type;type:int;not null" json:"DEVICE_TYPE"`
	DeviceID    int       `gorm:"column:device_id;type:int;not null" json:"DEVICE_ID"`
	DeviceName  string    `gorm:"column:device_name;type:varchar(256);not null" json:"DEVICE_NAME"`
	IconID      int       `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID      int       `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	CHostID     int       `gorm:"column:chost_id;type:int;default:null" json:"CHOST_ID"`
	CHostName   string    `gorm:"column:chost_name;type:varchar(256);default:null" json:"CHOST_NAME"`
	PodNodeID   int       `gorm:"column:pod_node_id;type:int;default:null" json:"POD_NODE_ID"`
	PodNodeName string    `gorm:"column:pod_node_name;type:varchar(256);default:null" json:"POD_NODE_NAME"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChVTapPort) TableName() string {
	return "ch_vtap_port"
}

type ChIPRelation struct {
	L3EPCID        int       `gorm:"primaryKey;column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	IP             string    `gorm:"primaryKey;column:ip;type:varchar(64);not null" json:"IP"`
	NATGWID        int       `gorm:"column:natgw_id;type:int;default:null" json:"NATGW_ID"`
	NATGWName      string    `gorm:"column:natgw_name;type:varchar(256);default:null" json:"NATGW_NAME"`
	LBID           int       `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	LBName         string    `gorm:"column:lb_name;type:varchar(256);default:null" json:"LB_NAME"`
	LBListenerID   int       `gorm:"column:lb_listener_id;type:int;default:null" json:"LB_LISTENER_ID"`
	LBListenerName string    `gorm:"column:lb_listener_name;type:varchar(256);default:null" json:"LB_LISTENER_NAME"`
	PodIngressID   int       `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	PodIngressName string    `gorm:"column:pod_ingress_name;type:varchar(256);default:null" json:"POD_INGRESS_NAME"`
	PodServiceID   int       `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodServiceName string    `gorm:"column:pod_service_name;type:varchar(256);default:null" json:"POD_SERVICE_NAME"`
	TeamID         int       `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	UpdatedAt      time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChIPRelation) TableName() string {
	return "ch_ip_relation"
}

type ChIPResource struct {
	IP             string    `gorm:"primaryKey;column:ip;type:varchar(64);not null" json:"IP"`
	SubnetID       int       `gorm:"primaryKey;column:subnet_id;type:int;not null" json:"SUBNET_ID"`
	SubnetName     string    `gorm:"column:subnet_name;type:varchar(256);default:null" json:"SUBNET_NAME"`
	RegionID       int       `gorm:"column:region_id;type:int;not null" json:"REGION_ID"`
	RegionName     string    `gorm:"column:region_name;type:varchar(256);default:null" json:"REGION_NAME"`
	AZID           int       `gorm:"column:az_id;type:int;not null" json:"AZ_ID"`
	AZName         string    `gorm:"column:az_name;type:varchar(256);default:null" json:"AZ_NAME"`
	HostID         int       `gorm:"column:host_id;type:int;not null" json:"HOST_ID"`
	HostName       string    `gorm:"column:host_name;type:varchar(256);default:null" json:"HOST_NAME"`
	CHostID        int       `gorm:"column:chost_id;type:int;not null" json:"CHOST_ID"`
	CHostName      string    `gorm:"column:chost_name;type:varchar(256);default:null" json:"CHOST_NAME"`
	L3EPCID        int       `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	L3EPCName      string    `gorm:"column:l3_epc_name;type:varchar(256);default:null" json:"L3_EPC_NAME"`
	RouterID       int       `gorm:"column:router_id;type:int;not null" json:"ROUTER_ID"`
	RouterName     string    `gorm:"column:router_name;type:varchar(256);default:null" json:"ROUTER_NAME"`
	DHCPGWID       int       `gorm:"column:dhcpgw_id;type:int;not null" json:"DHCPGW_ID"`
	DHCPGWName     string    `gorm:"column:dhcpgw_name;type:varchar(256);default:null" json:"DHCPGW_NAME"`
	LBID           int       `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	LBName         string    `gorm:"column:lb_name;type:varchar(256);default:null" json:"LB_NAME"`
	LBListenerID   int       `gorm:"column:lb_listener_id;type:int;default:null" json:"LB_LISTENER_ID"`
	LBListenerName string    `gorm:"column:lb_listener_name;type:varchar(256);default:null" json:"LB_LISTENER_NAME"`
	NATGWID        int       `gorm:"column:natgw_id;type:int;default:null" json:"NATGW_ID"`
	NATGWName      string    `gorm:"column:natgw_name;type:varchar(256);default:null" json:"NATGW_NAME"`
	RedisID        int       `gorm:"column:redis_id;type:int;not null" json:"REDIS_ID"`
	RedisName      string    `gorm:"column:redis_name;type:varchar(256);default:null" json:"REDIS_NAME"`
	RDSID          int       `gorm:"column:rds_id;type:int;not null" json:"RDS_ID"`
	RDSName        string    `gorm:"column:rds_name;type:varchar(256);default:null" json:"RDS_NAME"`
	PodClusterID   int       `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodClusterName string    `gorm:"column:pod_cluster_name;type:varchar(256);default:null" json:"POD_CLUSTER_NAME"`
	PodNSID        int       `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	PodNSName      string    `gorm:"column:pod_ns_name;type:varchar(256);default:null" json:"POD_NS_NAME"`
	PodNodeID      int       `gorm:"column:pod_node_id;type:int;not null" json:"POD_NODE_ID"`
	PodNodeName    string    `gorm:"column:pod_node_name;type:varchar(256);default:null" json:"POD_NODE_NAME"`
	PodIngressID   int       `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	PodIngressName string    `gorm:"column:pod_ingress_name;type:varchar(256);default:null" json:"POD_INGRESS_NAME"`
	PodServiceID   int       `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodServiceName string    `gorm:"column:pod_service_name;type:varchar(256);default:null" json:"POD_SERVICE_NAME"`
	PodGroupID     int       `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	PodGroupName   string    `gorm:"column:pod_group_name;type:varchar(256);default:null" json:"POD_GROUP_NAME"`
	PodID          int       `gorm:"column:pod_id;type:int;default:null" json:"POD_ID"`
	PodName        string    `gorm:"column:pod_name;type:varchar(256);default:null" json:"POD_NAME"`
	UID            string    `gorm:"column:uid;type:char(64);default:null" json:"UID"`
	UpdatedAt      time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChIPResource) TableName() string {
	return "ch_ip_resource"
}

type ChNetwork struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Name            string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int" json:"L3_EPC_ID"`
}

func (ChNetwork) TableName() string {
	return "ch_subnet"
}

type ChPod struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	PodNodeID    int    `gorm:"column:pod_node_id;type:int;not null" json:"POD_NODE_ID"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodGroupID   int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPodCluster struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Name            string `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodGroup struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	PodGroupType int    `gorm:"column:pod_group_type;type:int;default:null" json:"POD_GROUP_TYPE"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPodNamespace struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChPodNamespace) TableName() string {
	return "ch_pod_ns"
}

type ChPodNode struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	IconID       int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChVTap struct {
	ID          int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name        string    `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	Type        int       `gorm:"column:type;type:int;not null" json:"TYPE"`
	TeamID      int       `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	HostID      int       `gorm:"column:host_id;type:int;default:null" json:"HOST_ID"`
	HostName    string    `gorm:"column:host_name;type:varchar(256);default:null" json:"HOST_NAME"`
	CHostID     int       `gorm:"column:chost_id;type:int;default:null" json:"CHOST_ID"`
	CHostName   string    `gorm:"column:chost_name;type:varchar(256);default:null" json:"CHOST_NAME"`
	PodNodeID   int       `gorm:"column:pod_node_id;type:int;default:null" json:"POD_NODE_ID"`
	PodNodeName string    `gorm:"column:pod_node_name;type:varchar(256);default:null" json:"POD_NODE_NAME"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChVTap) TableName() string {
	return "ch_vtap"
}

type ChTapType struct {
	Value     int       `gorm:"primaryKey;column:value;type:int;not null" json:"VALUE"`
	Name      string    `gorm:"column:name;type:varchar(64);default:null" json:"NAME"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChLBListener struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name   string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	TeamID int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	// UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChLBListener) TableName() string {
	return "ch_lb_listener"
}

type ChPodIngress struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int;not null" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPodK8sLabel struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodK8sLabels struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Labels          string `gorm:"column:labels;type:text;default:null" json:"LABELS"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodServiceK8sLabel struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodServiceK8sLabels struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Labels          string `gorm:"column:labels;type:text;default:null" json:"LABELS"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChStringEnum struct {
	TagName       string    `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value         string    `gorm:"primaryKey;column:value;type:varchar(256);default:null" json:"VALUE"`
	NameZH        string    `gorm:"column:name_zh;type:varchar(256);default:null" json:"NAME_ZH"`
	NameEN        string    `gorm:"column:name_en;type:varchar(256);default:null" json:"NAME_EN"`
	DescriptionZH string    `gorm:"column:description_zh;type:varchar(256);default:null" json:"DESCRIPTION_ZH"`
	DescriptionEN string    `gorm:"column:description_en;type:varchar(256);default:null" json:"DESCRIPTION_EN"`
	UpdatedAt     time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChIntEnum struct {
	TagName       string    `gorm:"primaryKey;column:tag_name;type:varchar(256);default:null" json:"TAG_NAME"`
	Value         int       `gorm:"primaryKey;column:value;type:int;default:0" json:"VALUE"`
	NameZH        string    `gorm:"column:name_zh;type:varchar(256);default:null" json:"NAME_ZH"`
	NameEN        string    `gorm:"column:name_en;type:varchar(256);default:null" json:"NAME_EN"`
	DescriptionZH string    `gorm:"column:description_zh;type:varchar(256);default:null" json:"DESCRIPTION_ZH"`
	DescriptionEN string    `gorm:"column:description_en;type:varchar(256);default:null" json:"DESCRIPTION_EN"`
	UpdatedAt     time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChNodeType struct {
	ResourceType *int      `gorm:"primaryKey;column:resource_type;type:int;not null" json:"RESOURCE_TYPE"`
	NodeType     string    `gorm:"column:node_type;type:varchar(256);default:null" json:"NODE_TYPE"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChChostCloudTag struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key      string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value    string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	TeamID   int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	// UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPodNSCloudTag struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

func (ChPodNSCloudTag) TableName() string {
	return "ch_pod_ns_cloud_tag"
}

type ChChostCloudTags struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	CloudTags string `gorm:"column:cloud_tags;type:text;default:null" json:"CLOUD_TAGS"`
	TeamID    int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID  int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	// UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPodNSCloudTags struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	CloudTags       string `gorm:"column:cloud_tags;type:text;default:null" json:"CLOUD_TAGS"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

func (ChPodNSCloudTags) TableName() string {
	return "ch_pod_ns_cloud_tags"
}

type ChOSAppTag struct {
	ID          int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Key         string    `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value       string    `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	TeamID      int       `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID    int       `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID int       `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChOSAppTag) TableName() string {
	return "ch_os_app_tag"
}

type ChOSAppTags struct {
	ID          int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	OSAPPTags   string    `gorm:"column:os_app_tags;type:text;default:null" json:"OS_APP_TAGS"`
	TeamID      int       `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID    int       `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID int       `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChOSAppTags) TableName() string {
	return "ch_os_app_tags"
}

type ChGProcess struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Name            string `gorm:"column:name;type:text;default:null" json:"NAME"`
	IconID          int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	CHostID         int    `gorm:"column:chost_id;type:int;not null" json:"CHOST_ID"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int" json:"L3_EPC_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

func (ChGProcess) TableName() string {
	return "ch_gprocess"
}

type ChPodK8sAnnotation struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodK8sAnnotations struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Annotations     string `gorm:"column:annotations;type:text;default:null" json:"ANNOTATIONS"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodServiceK8sAnnotation struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodServiceK8sAnnotations struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Annotations     string `gorm:"column:annotations;type:text;default:null" json:"ANNOTATIONS"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodK8sEnv struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Key             string `gorm:"primaryKey;column:key;type:varchar(256);default:null" json:"KEY"`
	Value           string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPodK8sEnvs struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	Envs            string `gorm:"column:envs;type:text;default:null" json:"ENVS"`
	L3EPCID         int    `gorm:"column:l3_epc_id;type:int;not null" json:"L3_EPC_ID"`
	PodNsID         int    `gorm:"column:pod_ns_id;type:int;not null" json:"POD_NS_ID"`
	TeamID          int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID        int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID     int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
}

type ChPrometheusLabelName struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPrometheusMetricName struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPrometheusMetricAPPLabelLayout struct {
	ID                  int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MetricName          string    `gorm:"column:metric_name;type:varchar(256);not null" json:"METRIC_NAME"`
	APPLabelName        string    `gorm:"column:app_label_name;type:varchar(256);not null" json:"APP_LABEL_NAME"`
	APPLabelColumnIndex uint8     `gorm:"column:app_label_column_index;type:int unsigned;not null" json:"APP_LABEL_COLUMN_INDEX"`
	UpdatedAt           time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChAPPLabel struct {
	LabelNameID  int       `gorm:"primaryKey;column:label_name_id;type:int;not null" json:"LABEL_NAME_ID"`
	LabelValueID int       `gorm:"primaryKey;column:label_value_id;type:int unsigned;not null" json:"LABEL_VALUE_ID"`
	LabelValue   string    `gorm:"column:label_value;type:text;not null" json:"LABEL_VALUE"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChAPPLabel) TableName() string {
	return "ch_app_label"
}

type ChTargetLabel struct {
	MetricID    int       `gorm:"primaryKey;column:metric_id;type:int;not null" json:"METRIC_ID"`
	LabelNameID int       `gorm:"primaryKey;column:label_name_id;type:int;not null" json:"LABEL_NAME_ID"`
	TargetID    int       `gorm:"primaryKey;column:target_id;type:int unsigned;not null" json:"TARGET_ID"`
	LabelValue  string    `gorm:"column:label_value;type:varchar(256);not null" json:"LABEL_VALUE"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPrometheusTargetLabelLayout struct {
	TargetID          int       `gorm:"primaryKey;column:target_id;type:int;not null" json:"TARGET_ID"`
	TargetLabelNames  string    `gorm:"column:target_label_names;type:text;not null" json:"TARGET_LABEL_NAMES"`
	TargetLabelValues string    `gorm:"column:target_label_values;type:text;not null" json:"TARGET_LABEL_VALUES"`
	UpdatedAt         time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}
type ChPodService struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name         string `gorm:"column:name;type:varchar(256)" json:"NAME"`
	PodClusterID int    `gorm:"column:pod_cluster_id;type:int" json:"POD_CLUSTER_ID"`
	PodNsID      int    `gorm:"column:pod_ns_id;type:int" json:"POD_NS_ID"`
	TeamID       int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID     int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	SubDomainID  int    `gorm:"column:sub_domain_id;type:int;default:0" json:"SUB_DOMAIN_ID"`
	// UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChChost struct {
	ChIDBase        `gorm:"embedded"`
	ChUpdatedAtBase `gorm:"embedded"`
	// ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name     string `gorm:"column:name;type:varchar(256)" json:"NAME"`
	L3EPCID  int    `gorm:"column:l3_epc_id;type:int" json:"L3_EPC_ID"`
	HostID   int    `gorm:"column:host_id;type:int" json:"HOST_ID"`
	Hostname string `gorm:"column:hostname;type:varchar(256)" json:"HOSTNAME"`
	IP       string `gorm:"column:ip;type:varchar(64)" json:"IP"`
	SubnetID int    `gorm:"column:subnet_id;type:int" json:"SUBNET_ID"`
	TeamID   int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
	// UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChPolicy struct {
	ACLGID     int       `gorm:"primaryKey;column:acl_gid;type:int;not null" json:"ACL_GID"`
	TunnelType int       `gorm:"primaryKey;column:tunnel_type;type:int;not null" json:"TUNNEL_TYPE"`
	ID         int       `gorm:"column:id;type:int;not null" json:"ID"`
	Name       string    `gorm:"column:name;type:varchar(256)" json:"NAME"`
	TeamID     int       `gorm:"column:team_id;type:int;default:1" json:"TEAM_ID"`
	UpdatedAt  time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChNpbTunnel struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(256)" json:"NAME"`
	TeamID    int       `gorm:"column:team_id;type:int;default:1" json:"TEAM_ID"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChAlarmPolicy struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:char(128)" json:"NAME"`
	Info      string    `gorm:"column:info;type:text" json:"INFO"`
	UserID    int       `gorm:"column:user_id;type:int" json:"USER_ID"`
	TeamID    int       `gorm:"column:team_id;type:int;default:1" json:"TEAM_ID"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChAlarmPolicy) TableName() string {
	return "ch_alarm_policy"
}

type ChUser struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(256)" json:"NAME"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

type ChCustomBizService struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(256)" json:"NAME"`
	IconID    int       `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	UID       string    `gorm:"column:uid;type:char(64);default:null" json:"UID"`
	TeamID    int       `gorm:"column:team_id;type:int;default:1" json:"TEAM_ID"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChCustomBizService) TableName() string {
	return "ch_custom_biz_service"
}

type ChCustomBizServiceFilter struct {
	ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	ClientFilter string    `gorm:"column:client_filter;type:text" json:"CLIENT_FILTER"`
	ServerFilter string    `gorm:"column:server_filter;type:text" json:"SERVER_FILTER"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime:now,type:timestamp" json:"UPDATED_AT"`
}

func (ChCustomBizServiceFilter) TableName() string {
	return "ch_custom_biz_service_filter"
}

type ChBizService struct {
	ChIDBase         `gorm:"embedded"`
	ChUpdatedAtBase  `gorm:"embedded"`
	Name             string `gorm:"column:name;type:varchar(256)" json:"NAME"`
	ServiceGroupName string `gorm:"column:service_group_name;type:varchar(256)" json:"SERVICE_GROUP_NAME"`
	IconID           int    `gorm:"column:icon_id;type:int;default:null" json:"ICON_ID"`
	TeamID           int    `gorm:"column:team_id;type:int;not null" json:"TEAM_ID"`
	DomainID         int    `gorm:"column:domain_id;type:int;not null" json:"DOMAIN_ID"`
}

func (ChBizService) TableName() string {
	return "ch_biz_service"
}
