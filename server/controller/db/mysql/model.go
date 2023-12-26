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

package mysql

import (
	"bytes"
	"compress/zlib"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"time"

	"gorm.io/gorm"
)

type Base struct {
	ID     int    `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null" json:"ID"`
	Lcuuid string `gorm:"unique;column:lcuuid;type:char(64)" json:"LCUUID"`
	// TODO add CreatedAt/UpdatedAt/DeletedAt
}

func (b Base) GetID() int {
	return b.ID
}

func (b *Base) SetID(id int) {
	b.ID = id
}

func (b Base) GetLcuuid() string {
	return b.Lcuuid
}

type OperatedTime struct {
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at;type:datetime" json:"CREATED_AT"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;column:updated_at;type:datetime" json:"UPDATED_AT"`
}

type SoftDeleteBase struct {
	OperatedTime
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;type:datetime;default:null" json:"DELETED_AT"`
}

type ResourceEvent struct {
	ID             int       `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null" json:"ID"`
	Domain         string    `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	SubDomain      string    `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	ResourceLcuuid string    `gorm:"column:resource_lcuuid;type:char(64);default:''" json:"RESOURCE_LCUUID"`
	Content        string    `gorm:"column:content;type:text" json:"CONTENT"`
	CreatedAt      time.Time `gorm:"autoCreateTime;column:created_at;type:datetime" json:"CREATED_AT"`
}

type DomainAdditionalResource struct {
	ID                int             `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null" json:"ID"`
	Domain            string          `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	Content           string          `gorm:"column:content;type:longtext" json:"CONTENT"`
	CompressedContent compressedBytes `gorm:"column:compressed_content;type:longblob" json:"COMPRESSED_CONTENT"`
	CreatedAt         time.Time       `gorm:"autoCreateTime;column:created_at;type:datetime" json:"CREATED_AT"`
}
type Process struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string    `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	VTapID         int       `gorm:"column:vtap_id;type:int;not null;default:0" json:"VTAP_ID"`
	PID            int       `gorm:"column:pid;type:int;not null;default:0" json:"PID"`
	ProcessName    string    `gorm:"column:process_name;type:varchar(256);default:''" json:"PROCESS_NAME"`
	CommandLine    string    `gorm:"column:command_line;type:text" json:"COMMAND_LINE"`
	UserName       string    `gorm:"column:user_name;type:varchar(256);default:''" json:"USER_NAME"`
	StartTime      time.Time `gorm:"autoCreateTime;column:start_time;type:datetime" json:"START_TIME"`
	OSAPPTags      string    `gorm:"column:os_app_tags;type:text" json:"OS_APP_TAGS"`
	SubDomain      string    `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string    `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
}

type Domain struct {
	Base         `gorm:"embedded"`
	OperatedTime `gorm:"embedded"`
	SyncedAt     *time.Time `gorm:"column:synced_at" json:"SYNCED_AT"`
	Name         string     `gorm:"column:name;type:varchar(64)" json:"NAME"`
	IconID       int        `gorm:"column:icon_id;type:int" json:"ICON_ID"`
	DisplayName  string     `gorm:"column:display_name;type:varchar(64);default:''" json:"DISPLAY_NAME"`
	ClusterID    string     `gorm:"column:cluster_id;type:char(64)" json:"CLUSTER_ID"`
	Type         int        `gorm:"column:type;type:int;default:0" json:"TYPE"` // 1.openstack 2.vsphere 3.nsp 4.tencent 5.filereader 6.aws 7.pingan 8.zstack 9.aliyun 10.huawei prv 11.k8s 12.simulation 13.huawei 14.qingcloud 15.qingcloud_private 16.F5 17.CMB_CMDB 18.azure 19.apsara_stack 20.tencent_tce 21.qingcloud_k8s 22.kingsoft_private 23.genesis 24.microsoft_acs 25.baidu_bce
	Config       string     `gorm:"column:config;type:text" json:"CONFIG"`
	ErrorMsg     string     `gorm:"column:error_msg;type:text" json:"ERROR_MSG"`
	Enabled      int        `gorm:"column:enabled;type:int;not null;default:1" json:"ENABLED"` // 0.false 1.true
	State        int        `gorm:"column:state;type:int;not null;default:1" json:"STATE"`     // 1.normal 2.deleting 3.exception
	ControllerIP string     `gorm:"column:controller_ip;type:char(64)" json:"CONTROLLER_IP"`
}

// TODO 最终可以与cloud模块命名统一，Domain -> DomainLcuuid

type SubDomain struct {
	Base         `gorm:"embedded"`
	OperatedTime `gorm:"embedded"`
	SyncedAt     *time.Time `gorm:"column:synced_at" json:"SYNCED_AT"`
	Domain       string     `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	Name         string     `gorm:"column:name;type:varchar(64);default:''" json:"NAME"`
	DisplayName  string     `gorm:"column:display_name;type:varchar(64);default:''" json:"DISPLAY_NAME"`
	CreateMethod int        `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	ClusterID    string     `gorm:"column:cluster_id;type:char(64);default:''" json:"CLUSTER_ID"`
	Config       string     `gorm:"column:config;type:text;default:''" json:"CONFIG"`
	ErrorMsg     string     `gorm:"column:error_msg;type:text;default:''" json:"ERROR_MSG"`
	Enabled      int        `gorm:"column:enabled;type:int;not null;default:1" json:"ENABLED"` // 0.false 1.true
	State        int        `gorm:"column:state;type:int;not null;default:1" json:"STATE"`     // 1.normal 2.deleting 3.exception
}

type Region struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string  `gorm:"column:name;type:varchar(64);default:''" json:"NAME"`
	CreateMethod   int     `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string  `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	Longitude      float64 `gorm:"column:longitude;type:double(7,4);default:null" json:"LONGITUDE"`
	Latitude       float64 `gorm:"column:latitude;type:double(7,4);default:null" json:"LATITUDE"`
}

type AZ struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(64);default:''" json:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
}

func (AZ) TableName() string {
	return "az"
}

type Host struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Type           int       `gorm:"column:type;type:int" json:"TYPE"`   // 1.Server 3.Gateway 4.DFI
	State          int       `gorm:"column:state;type:int" json:"STATE"` // 0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception
	Name           string    `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string    `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Description    string    `gorm:"column:description;type:varchar(256);default:''" json:"DESCRIPTION"`
	IP             string    `gorm:"column:ip;type:char(64);default:''" json:"IP"`
	HType          int       `gorm:"column:htype;type:int" json:"HTYPE"`                           // 1. Xen host 2. VMware host 3. KVM host 4. Public cloud host 5. Hyper-V
	CreateMethod   int       `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	UserName       string    `gorm:"column:user_name;type:varchar(64);default:''" json:"USER_NAME"`
	UserPasswd     string    `gorm:"column:user_passwd;type:varchar(64);default:''" json:"USER_PASSWD"`
	VCPUNum        int       `gorm:"column:vcpu_num;type:int;default:0" json:"VCPU_NUM"`
	MemTotal       int       `gorm:"column:mem_total;type:int;default:0" json:"MEM_TOTAL"` // unit: M
	AZ             string    `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string    `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Domain         string    `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	SyncedAt       time.Time `gorm:"column:synced_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"SYNCED_AT"`
	ExtraInfo      string    `gorm:"column:extra_info;type:text;default:''" json:"EXTRA_INFO"`
}

func (Host) TableName() string {
	return "host_device"
}

type VM struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	State          int    `gorm:"index:state_server_index;column:state;type:int;not null" json:"STATE"` // 0.Temp 1.Creating 2.Created 3.To run 4.Running 5.To suspend 6.Suspended 7.To resume 8. To stop 9.Stopped 10.Modifing 11.Exception 12.Destroying
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	HType          int    `gorm:"column:htype;type:int;default:1" json:"HTYPE"`                 // 1.vm-c 2.bm-c 3.vm-n 4.bm-n 5.vm-s 6.bm-s
	LaunchServer   string `gorm:"index:state_server_index;column:launch_server;type:char(64);default:''" json:"LAUNCH_SERVER"`
	CloudTags      string `gorm:"column:cloud_tags;type:text;default:''" json:"CLOUD_TAGS"` // separated by ,
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

func (VM) TableName() string {
	return "vm"
}

type VMPodNodeConnection struct {
	Base      `gorm:"embedded"`
	VMID      int    `gorm:"column:vm_id;type:int;default:null" json:"VM_ID"`
	PodNodeID int    `gorm:"column:pod_node_id;type:int;default:null" json:"POD_NODE_ID"`
	Domain    string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	SubDomain string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

func (VMPodNodeConnection) TableName() string {
	return "vm_pod_node_connection"
}

type VMSecurityGroup struct {
	Base            `gorm:"embedded"`
	SecurityGroupID int `gorm:"column:sg_id;type:int;not null" json:"SG_ID"`
	VMID            int `gorm:"column:vm_id;type:int;not null" json:"VM_ID"`
	Priority        int `gorm:"column:priority;type:int;not null" json:"PRIORITY"`
}

func (VMSecurityGroup) TableName() string {
	return "vm_security_group"
}

type Contact struct {
	Base         `gorm:"embedded"`
	Name         string    `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Mobile       string    `gorm:"column:mobile;type:char(13);default:''" json:"MOBILE"`
	Email        string    `gorm:"column:email;type:varchar(128);default:''" json:"EMAIL"`
	Company      string    `gorm:"column:company;type:varchar(128);default:''" json:"COMPANY"`
	PushEmail    string    `gorm:"column:push_email;type:text;default:null" json:"PUSH_EMAIL"`
	Domain       string    `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	AlarmPush    int       `gorm:"column:alarm_push;type:int;default:0" json:"ALARM_PUSH"`
	ReportPush   int       `gorm:"column:report_push;type:int;default:0" json:"REPORT_PUSH"`
	Deleted      int       `gorm:"column:deleted;type:int;default:0" json:"DELETED"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:datetime;default:null" json:"UPDATED_AT"`
}

type VPCContact struct {
	Base         `gorm:"embedded"`
	CreateMethod int `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	VPCID        int `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	ContactID    int `gorm:"column:contact_id;type:int;default:0" json:"CONTACT_ID"`
}

func (VPCContact) TableName() string {
	return "epc_contact"
}

type VPC struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Domain         string `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"` // TODO delete in future
	TunnelID       int    `gorm:"column:tunnel_id;type:int;default:0" json:"TUNNEL_ID"`
	Mode           int    `gorm:"column:mode;type:int;default:2" json:"MODE"` //  1:route, 2:transparent
	CIDR           string `gorm:"column:cidr;type:char(64);default:''" json:"CIDR"`
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

func (VPC) TableName() string {
	return "epc"
}

type Network struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	State          int    `gorm:"column:state;type:int;not null" json:"STATE"`        // 0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.Destroyed
	NetType        int    `gorm:"column:net_type;type:int;default:4" json:"NET_TYPE"` // 1.CTRL 2.SERVICE 3.WAN 4.LAN
	Name           string `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Description    string `gorm:"column:description;type:varchar(256);default:''" json:"DESCRIPTION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	ISP            int    `gorm:"column:isp;type:int;default:0" json:"ISP"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	SegmentationID int    `gorm:"column:segmentation_id;type:int;default:0" json:"SEGMENTATION_ID"`
	TunnelID       int    `gorm:"column:tunnel_id;type:int;default:0" json:"TUNNEL_ID"`
	Shared         bool   `gorm:"column:shared;type:int;default:0" json:"SHARED"`
	Topped         int    `gorm:"column:topped;type:int;default:0" json:"TOPPED"`
	IsVIP          int    `gorm:"column:is_vip;type:int;default:0" json:"IS_VIP"`
}

func (Network) TableName() string {
	return "vl2"
}

type Subnet struct {
	Base      `gorm:"embedded"`
	Prefix    string `gorm:"column:prefix;type:char(64);default:''" json:"PREFIX"`
	Netmask   string `gorm:"column:netmask;type:char(64);default:''" json:"NETMASK"`
	NetworkID int    `gorm:"column:vl2id;type:int;default:null" json:"VL2ID"`
	NetIndex  int    `gorm:"column:net_index;type:int;default:0" json:"NET_INDEX"`
	Name      string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label     string `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	SubDomain string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

func (Subnet) TableName() string {
	return "vl2_net"
}

type VRouter struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	State          int    `gorm:"index:state_server_index;column:state;type:int;not null" json:"STATE"` // 0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.To run 7.Running 8.To stop 9.Stopped
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	Description    string `gorm:"column:description;type:varchar(256);default:''" json:"DESCRIPTION"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	GWLaunchServer string `gorm:"index:state_server_index;column:gw_launch_server;type:char(64);default:''" json:"GW_LAUNCH_SERVER"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"` // TODO delete in future
}

func (VRouter) TableName() string {
	return "vnet"
}

type RoutingTable struct {
	Base        `gorm:"embedded"`
	VRouterID   int    `gorm:"column:vnet_id;type:int;default:null" json:"VNET_ID"`
	Destination string `gorm:"column:destination;type:text;default:''" json:"DESTINATION"`
	NexthopType string `gorm:"column:nexthop_type;type:text;default:''" json:"NEXTHOP_TYPE"`
	Nexthop     string `gorm:"column:nexthop;type:text;default:''" json:"NEXTHOP"`
}

type DHCPPort struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
}

func (DHCPPort) TableName() string {
	return "dhcp_port"
}

type VInterface struct {
	Base         `gorm:"embedded"`
	Name         string    `gorm:"column:name;type:char(64);default:''" json:"NAME"`
	Index        int       `gorm:"column:ifindex;type:int;not null" json:"IFINDEX"`
	State        int       `gorm:"column:state;type:int;not null" json:"STATE"`                  // 1. Attached 2.Detached 3.Exception
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Type         int       `gorm:"column:iftype;type:int;default:0" json:"IFTYPE"`               // 0.Unknown 1.Control 2.Service 3.WAN 4.LAN 5.Trunk 6.Tap 7.Tool
	Mac          string    `gorm:"index:mac_index;column:mac;type:char(32);default:''" json:"MAC"`
	VMac         string    `gorm:"column:vmac;type:char(32);default:''" json:"VMAC"`
	TapMac       string    `gorm:"column:tap_mac;type:char(32);default:''" json:"TAP_MAC"`
	NetworkID    int       `gorm:"column:subnetid;type:int;default:0" json:"SUBNETID"` // vl2 id
	VlanTag      int       `gorm:"column:vlantag;type:int;default:0" json:"VLANTAG"`
	DeviceType   int       `gorm:"column:devicetype;type:int;default:null" json:"DEVICETYPE"` // Type 0.unknown 1.vm 2.vgw 3.third-party-device 4.vmwaf 5.NSP-vgateway 6.host-device 7.network-device 9.DHCP-port 10.pod 11.pod_service 12. redis_instance 13. rds_instance 14. pod_node 15. load_balance 16. nat_gateway
	DeviceID     int       `gorm:"column:deviceid;type:int;default:null" json:"DEVICEID"`     // unknown: Senseless ID, vm: vm ID, vgw/NSP-vgateway: vnet ID, third-party-device: third_party_device ID, vmwaf: vmwaf ID, host-device: host_device ID, network-device: network_device ID
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region       string    `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

func (VInterface) TableName() string {
	return "vinterface"
}

type LANIP struct { // TODO 添加region字段
	Base         `gorm:"embedded"`
	IP           string    `gorm:"column:ip;type:char(64);default:''" json:"IP"`
	Netmask      string    `gorm:"column:netmask;type:char(64);default:''" json:"NETMASK"`
	Gateway      string    `gorm:"column:gateway;type:char(64);default:''" json:"GATEWAY"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	NetworkID    int       `gorm:"column:vl2id;type:int;default:null" json:"VL2ID"`
	NetIndex     int       `gorm:"column:net_index;type:int;default:0" json:"NET_INDEX"`
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	VInterfaceID int       `gorm:"column:vifid;type:int;default:null" json:"VINTERFACE_ID"`
	SubnetID     int       `gorm:"column:vl2_net_id;type:int;default:0" json:"SUBNET_ID"`
	ISP          int       `gorm:"column:isp;type:int;default:0" json:"ISP"` // Used for multi-ISP access
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

func (LANIP) TableName() string {
	return "vinterface_ip"
}

type WANIP struct {
	Base         `gorm:"embedded"`
	IP           string    `gorm:"column:ip;type:char(64);default:''" json:"IP"`
	Alias        string    `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Netmask      int       `gorm:"column:netmask;type:int;default:null" json:"NETMASK"`
	Gateway      string    `gorm:"column:gateway;type:char(64);default:''" json:"GATEWAY"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	ISP          int       `gorm:"column:isp;type:int;default:null" json:"ISP"`
	VInterfaceID int       `gorm:"column:vifid;type:int;default:0" json:"VINTERFACE_ID"`
	SubnetID     int       `gorm:"column:vl2_net_id;type:int;default:0" json:"SUBNET_ID"`
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region       string    `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

func (WANIP) TableName() string {
	return "ip_resource"
}

type FloatingIP struct {
	Base      `gorm:"embedded"`
	Domain    string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region    string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	VPCID     int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	NetworkID int    `gorm:"column:vl2_id;type:int;default:null" json:"VL2_ID"` // TODO json字段是否能修改，需返回给前端？
	VMID      int    `gorm:"column:vm_id;type:int;default:null" json:"VM_ID"`
	IP        string `gorm:"column:ip;type:char(64);default:''" json:"IP"`
}

func (FloatingIP) TableName() string {
	return "floatingip"
}

type SecurityGroup struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:varchar(64);default:''" json:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Topped         int    `gorm:"column:topped;type:int;default:0" json:"TOPPED"`
}

type SecurityGroupRule struct {
	Base            `gorm:"embedded"`
	SecurityGroupID int    `gorm:"column:sg_id;type:int;not null" json:"SG_ID"`
	Direction       int    `gorm:"column:direction;type:tinyint(1);not null;default:0" json:"DIRECTION"` // 0.Unknow 1.Ingress 2.Egress
	Protocol        string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	EtherType       int    `gorm:"column:ethertype;type:tinyint(1);not null;default:0" json:"ETHERTYPE"` // 0.Unknow 1.IPv4 2.IPv6
	LocalPortRange  string `gorm:"column:local_port_range;type:text;default:''" json:"LOCAL_PORT_RANGE"`
	RemotePortRange string `gorm:"column:remote_port_range;type:text;default:''" json:"REMOTE_PORT_RANGE"`
	Local           string `gorm:"column:local;type:text;default:''" json:"LOCAL"`
	Remote          string `gorm:"column:remote;type:text;default:''" json:"REMOTE"`
	Priority        int    `gorm:"column:priority;type:int;not null" json:"PRIORITY"`
	Action          int    `gorm:"column:action;type:tinyint(1);not null;default:0" json:"ACTION"` // 0.Unknow 1.Accept 2.Drop
}

type NATGateway struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	FloatingIPs    string `gorm:"column:floating_ips;type:text;default:''" json:"FLOATING_IPS"` // separated by ,
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"` // TODO delete in future
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

func (NATGateway) TableName() string {
	return "nat_gateway"
}

type NATRule struct {
	Base           `gorm:"embedded"`
	NATGatewayID   int    `gorm:"column:nat_id;type:int;default:0" json:"NAT_ID"`
	Type           string `gorm:"column:type;type:char(16);default:''" json:"TYPE"`
	Protocol       string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	FloatingIP     string `gorm:"column:floating_ip;type:char(64);default:''" json:"FLOATING_IP"`
	FloatingIPPort int    `gorm:"column:floating_ip_port;type:int;default:null" json:"FLOATING_IP_PORT"`
	FixedIP        string `gorm:"column:fixed_ip;type:char(64);default:''" json:"FIXED_IP"`
	FixedIPPort    int    `gorm:"column:fixed_ip_port;type:int;default:null" json:"FIXED_IP_PORT"`
	VInterfaceID   int    `gorm:"column:port_id;type:int;default:null" json:"PORT_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (NATRule) TableName() string {
	return "nat_rule"
}

type NATVMConnection struct {
	Base         `gorm:"embedded"`
	NATGatewayID int    `gorm:"column:nat_id;type:int;default:null" json:"NAT_ID"`
	VMID         int    `gorm:"column:vm_id;type:int;default:null" json:"VM_ID"`
	Domain       string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (NATVMConnection) TableName() string {
	return "nat_vm_connection"
}

type LB struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	Model          int    `gorm:"column:model;type:int;default:0" json:"MODEL"` // 1.Internal 2.External
	VIP            string `gorm:"column:vip;type:text;default:''" json:"VIP"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"` // TODO delete in future
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

func (LB) TableName() string {
	return "lb"
}

type LBListener struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	LBID           int    `gorm:"column:lb_id;type:int;default:0" json:"LB_ID"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	IPs            string `gorm:"column:ips;type:text;default:''" json:"IPS"`           // separated by ,
	SNATIPs        string `gorm:"column:snat_ips;type:text;default:''" json:"SNAT_IPS"` // separated by ,
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	Port           int    `gorm:"column:port;type:int;default:null" json:"PORT"`
	Protocol       string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (LBListener) TableName() string {
	return "lb_listener"
}

type LBTargetServer struct {
	Base         `gorm:"embedded"`
	LBID         int    `gorm:"column:lb_id;type:int;default:0" json:"LB_ID"`
	LBListenerID int    `gorm:"column:lb_listener_id;type:int;default:0" json:"LB_LISTENER_ID"`
	VPCID        int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	Type         int    `gorm:"column:type;type:int;default:0" json:"TYPE"` // 1.VM 2.IP
	IP           string `gorm:"column:ip;type:char(64);default:''" json:"IP"`
	VMID         int    `gorm:"column:vm_id;type:int;default:0" json:"VM_ID"`
	Port         int    `gorm:"column:port;type:int;default:null" json:"PORT"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	Domain       string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (LBTargetServer) TableName() string {
	return "lb_target_server"
}

type LBVMConnection struct {
	Base   `gorm:"embedded"`
	LBID   int    `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	VMID   int    `gorm:"column:vm_id;type:int;default:null" json:"VM_ID"`
	Domain string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (LBVMConnection) TableName() string {
	return "lb_vm_connection"
}

type PeerConnection struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	LocalVPCID     int    `gorm:"column:local_epc_id;type:int;default:0" json:"LOCAL_VPC_ID"`
	RemoteVPCID    int    `gorm:"column:remote_epc_id;type:int;default:0" json:"REMOTE_VPC_ID"`
	LocalRegionID  int    `gorm:"column:local_region_id;type:int;default:0" json:"LOCAL_REGION_ID"`
	RemoteRegionID int    `gorm:"column:remote_region_id;type:int;default:0" json:"REMOTE_REGION_ID"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" json:"CREATE_METHOD"` // 0.learning 1.user_defined
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type CEN struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	VPCIDs         string `gorm:"column:epc_ids;type:text;default:''" json:"VPC_IDS"` // separated by ,
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (CEN) TableName() string {
	return "cen"
}

type RDSInstance struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	State          int    `gorm:"column:state;type:tinyint(1);not null;default:0" json:"STATE"` // 0. Unknown 1. Running 2. Recovering
	Domain         string `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	Type           int    `gorm:"column:type;type:int;default:0" json:"TYPE"` // 0. Unknown 1. MySQL 2. SqlServer 3. PPAS 4. PostgreSQL 5. MariaDB
	Version        string `gorm:"column:version;type:char(64);default:''" json:"VERSION"`
	Series         int    `gorm:"column:series;type:tinyint(1);not null;default:0" json:"SERIES"` // 0. Unknown 1. basic 2. HA
	Model          int    `gorm:"column:model;type:tinyint(1);not null;default:0" json:"MODEL"`   // 0. Unknown 1. Primary 2. Readonly 3. Temporary 4. Disaster recovery 5. share
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

func (RDSInstance) TableName() string {
	return "rds_instance"
}

type RedisInstance struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" json:"LABEL"`
	State          int    `gorm:"column:state;type:tinyint(1);not null;default:0" json:"STATE"` // 0. Unknown 1. Running 2. Recovering
	Domain         string `gorm:"column:domain;type:char(64);default:''" json:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" json:"VPC_ID"`
	Version        string `gorm:"column:version;type:char(64);default:''" json:"VERSION"`
	InternalHost   string `gorm:"column:internal_host;type:varchar(128);default:''" json:"INTERNAL_HOST"`
	PublicHost     string `gorm:"column:public_host;type:varchar(128);default:''" json:"PUBLIC_HOST"`
	UID            string `gorm:"column:uid;type:char(64);default:''" json:"UID"`
}

type PodCluster struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	ClusterName    string `gorm:"column:cluster_name;type:varchar(256);default:''" json:"CLUSTER_NAME"`
	Version        string `gorm:"column:version;type:varchar(256);default:''" json:"VERSION"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodNamespace struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	CloudTags      string `gorm:"column:cloud_tags;type:text;default:''" json:"CLOUD_TAGS"` // separated by ,
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodNode struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Type           int    `gorm:"column:type;type:int;default:null" json:"TYPE"`               // 1: Master 2: Node
	ServerType     int    `gorm:"column:server_type;type:int;default:null" json:"SERVER_TYPE"` // 1: Host 2: VM
	State          int    `gorm:"column:state;type:int;default:1" json:"STATE"`                // 0: Exception 1: Normal
	IP             string `gorm:"column:ip;type:char(64);default:''" json:"IP"`
	VCPUNum        int    `gorm:"column:vcpu_num;type:int;default:0" json:"VCPU_NUM"`
	MemTotal       int    `gorm:"column:mem_total;type:int;default:0" json:"MEM_TOTAL"` // unit: M
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodIngress struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" json:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodIngressRule struct {
	Base         `gorm:"embedded"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	Host         string `gorm:"column:host;type:text;default:''" json:"HOST"`
	PodIngressID int    `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

type PodIngressRuleBackend struct {
	Base             `gorm:"embedded"`
	Path             string `gorm:"column:path;type:text;default:''" json:"PATH"`
	Port             int    `gorm:"column:port;type:int;default:null" json:"PORT"`
	PodServiceID     int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	PodIngressRuleID int    `gorm:"column:pod_ingress_rule_id;type:int;default:null" json:"POD_INGRESS_RULE_ID"`
	PodIngressID     int    `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	SubDomain        string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

type PodService struct {
	Base             `gorm:"embedded"`
	SoftDeleteBase   `gorm:"embedded"`
	Name             string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Label            string `gorm:"column:label;type:text;default:''" json:"LABEL"` // separated by ,
	Alias            string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Type             int    `gorm:"column:type;type:int;default:null" json:"TYPE"`        // 1: ClusterIP 2: NodePort
	Selector         string `gorm:"column:selector;type:text;default:''" json:"SELECTOR"` // separated by ,
	ServiceClusterIP string `gorm:"column:service_cluster_ip;type:char(64);default:''" json:"SERVICE_CLUSTER_IP"`
	PodIngressID     int    `gorm:"column:pod_ingress_id;type:int;default:null" json:"POD_INGRESS_ID"`
	PodNamespaceID   int    `gorm:"column:pod_namespace_id;type:int;default:null" json:"POD_NAMESPACE_ID"`
	PodClusterID     int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	VPCID            int    `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"`
	AZ               string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region           string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain        string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain           string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodServicePort struct {
	Base         `gorm:"embedded"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	Port         int    `gorm:"column:port;type:int;default:null" json:"PORT"`
	TargetPort   int    `gorm:"column:target_port;type:int;default:null" json:"TARGET_PORT"`
	NodePort     int    `gorm:"column:node_port;type:int;default:null" json:"NODE_PORT"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

type PodGroup struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Type           int    `gorm:"column:type;type:int;default:null" json:"TYPE"` // 1: Deployment 2: StatefulSet 3: ReplicationController
	PodNum         int    `gorm:"column:pod_num;type:int;default:1" json:"POD_NUM"`
	Label          string `gorm:"column:label;type:text;default:''" json:"LABEL"` // separated by ,
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" json:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type PodGroupPort struct {
	Base         `gorm:"embedded"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" json:"PROTOCOL"`
	Port         int    `gorm:"column:port;type:int;default:null" json:"PORT"`
	PodGroupID   int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" json:"POD_SERVICE_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
}

type PodReplicaSet struct {
	Base           `gorm:"embedded"`
	SoftDeleteBase `gorm:"embedded"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	Label          string `gorm:"column:label;type:text;default:''" json:"LABEL"` // separated by ,
	PodNum         int    `gorm:"column:pod_num;type:int;default:1" json:"POD_NUM"`
	PodGroupID     int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" json:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

func (PodReplicaSet) TableName() string {
	return "pod_rs"
}

type Pod struct {
	Base            `gorm:"embedded"`
	SoftDeleteBase  `gorm:"embedded"`
	Name            string `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Alias           string `gorm:"column:alias;type:char(64);default:''" json:"ALIAS"`
	State           int    `gorm:"column:state;type:int;not null" json:"STATE"`    // 0.Exception 1.Running
	Label           string `gorm:"column:label;type:text;default:''" json:"LABEL"` // separated by ,
	PodReplicaSetID int    `gorm:"column:pod_rs_id;type:int;default:null" json:"POD_RS_ID"`
	PodGroupID      int    `gorm:"column:pod_group_id;type:int;default:null" json:"POD_GROUP_ID"`
	PodNamespaceID  int    `gorm:"column:pod_namespace_id;type:int;default:null" json:"POD_NAMESPACE_ID"`
	PodNodeID       int    `gorm:"column:pod_node_id;type:int;default:null" json:"POD_NODE_ID"`
	PodClusterID    int    `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	VPCID           int    `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"`
	AZ              string `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region          string `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	SubDomain       string `gorm:"column:sub_domain;type:char(64);default:''" json:"SUB_DOMAIN"`
	Domain          string `gorm:"column:domain;type:char(64);not null" json:"DOMAIN"`
}

type Business struct {
	ID          int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name        string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	Description string    `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
	Type        int       `gorm:"column:type;type:int;default:1" json:"TYPE"`        // 1-data center; 2-ip; 3-vpc; 4-WAN; 5-NPB; 6-diagnose; 21-tmp ip; 31-tmp vpc
	VPCID       int       `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"` // for vpc type
	NetworkID   int       `gorm:"column:vl2_id;type:int;default:null" json:"VL2_ID"` // for ip type
	State       int       `gorm:"column:state;type:int;default:1" json:"STATE"`      // 0-disable; 1-enable
	CreatedAt   time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt   time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid      string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

type ResourceGroup struct {
	ID            int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	BusinessID    int       `gorm:"column:business_id;type:int;not null" json:"BUSINESS_ID"`
	Lcuuid        string    `gorm:"column:lcuuid;type:varchar(64);not null" json:"LCUUID"`
	Name          string    `gorm:"column:name;type:varchar(200);not null;default:''" json:"NAME"`
	Type          int       `gorm:"column:type;type:int;not null" json:"TYPE"`            // 1:vm, 2:ip, 3: anonymous vm, 4: anonymous ip, 5: reserved for pod_group, 6: anonymous pod_group, 7: reserved for pod_service, 8: anonymous pod_service, 81: anonymous pod_service as pod_group, 9：lb_bk_rule, 10：reserved for anonymous lb_bk_rule, 11: tmp vm, 21: tmp ip, 13: reserve for vl2, 14: anonymous vl2
	IPType        int       `gorm:"column:ip_type;type:int;default:null" json:"IP_TYPE"`  // 1: single ip, 2: ip range, 3: cidr, 4.mix [1, 2, 3]
	IPs           string    `gorm:"column:ips;type:text;default:null" json:"IPS"`         // ips separated by ,
	VMIDs         string    `gorm:"column:vm_ids;type:text;default:null" json:"VM_IDS"`   // vm ids separated by ,
	NetworkIDs    string    `gorm:"column:vl2_ids;type:text;default:null" json:"VL2_IDS"` // vl2 ids separated by ,
	VPCID         int       `gorm:"column:epc_id;type:int;default:null" json:"VPC_ID"`
	PodClusterID  int       `gorm:"column:pod_cluster_id;type:int;default:null" json:"POD_CLUSTER_ID"`
	PodGroupIDs   string    `gorm:"column:pod_group_ids;type:text;default:null" json:"POD_GROUP_IDS"`     // pod group ids separated by ,
	PodServiceIDs string    `gorm:"column:pod_service_ids;type:text;default:null" json:"POD_SERVICE_IDS"` // pod service ids separated by ,
	LBID          int       `gorm:"column:lb_id;type:int;default:null" json:"LB_ID"`
	LBListenerID  int       `gorm:"column:lb_listener_id;type:int;default:null" json:"LB_LISTENER_ID"`
	ExtraInfoIDs  string    `gorm:"column:extra_info_ids;type:string;default:null" json:"EXTRA_INFO_IDS"`
	IconID        int       `gorm:"column:icon_id;type:int;default:-2" json:"ICON_ID"`
	CreatedAt     time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt     time.Time `gorm:"column:updated_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

type ResourceGroupPort struct {
	ID              int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name            string    `gorm:"column:name;type:varchar(256);default:''" json:"NAME"`
	Ports           string    `gorm:"column:ports;type:text;default:null" json:"PORTS"` // Save server ports list when type is customize
	BusinessID      int       `gorm:"column:business_id;type:int;not null" json:"BUSINESS_ID"`
	ResourceGroupID int       `gorm:"column:rg_id;type:int;not null" json:"RG_ID"`
	CreatedAt       time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt       time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid          string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

type TapType struct {
	ID             int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name           string `gorm:"column:name;type:char(64);not null" json:"NAME"`
	Type           int    `gorm:"column:type;type:int;not null;default:1" json:"TYPE"` // 1:packet, 2:sFlow, 3:NetFlow V5 4:NetStream v5
	Region         string `gorm:"column:region;type:char(64);default:null" json:"REGION"`
	Value          int    `gorm:"column:value;type:int;not null" json:"VALUE"`
	VLAN           int    `gorm:"column:vlan;type:int;default:null" json:"VLAN"`
	SrcIP          string `gorm:"column:src_ip;type:char(64);default:null" json:"SRC_IP"`
	InterfaceIndex uint   `gorm:"column:interface_index;type:int unsigned;default:null" json:"INTERFACE_INDEX"` // 1 ~ 2^32-1
	InterfaceName  string `gorm:"column:interface_name;type:char(64);default:null" json:"INTERFACE_NAME"`
	SamplingRate   uint   `gorm:"column:sampling_rate;type:int unsigned;default:null" json:"SAMPLING_RATE"` // 1 ~ 2^32-1
	Description    string `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
	Lcuuid         string `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

type Controller struct {
	ID                 int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	State              int       `gorm:"column:state;type:int;default:null" json:"STATE"` // 0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception
	Name               string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	Description        string    `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
	IP                 string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	NATIP              string    `gorm:"column:nat_ip;type:char(64);default:null" json:"NAT_IP"`
	CPUNum             int       `gorm:"column:cpu_num;type:int;default:0" json:"CPU_NUM"` // logical number of cpu
	MemorySize         int64     `gorm:"column:memory_size;type:bigint;default:0" json:"MEMORY_SIZE"`
	Arch               string    `gorm:"column:arch;type:varchar(256);default:null" json:"ARCH"`
	Os                 string    `gorm:"column:os;type:varchar(256);default:null" json:"OS"`
	KernelVersion      string    `gorm:"column:kernel_version;type:varchar(256);default:null" json:"KERNEL_VERSION"`
	VTapMax            int       `gorm:"column:vtap_max;type:int;default:2000" json:"VTAP_MAX"`
	SyncedAt           time.Time `gorm:"column:synced_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"SYNCED_AT"`
	NATIPEnabled       int       `gorm:"column:nat_ip_enabled;default:0" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	NodeType           int       `gorm:"column:node_type;type:int;default:2" json:"NODE_TYPE"`  // region node type 1.master 2.slave
	RegionDomainPrefix string    `gorm:"column:region_domain_prefix;type:varchar(256);default:''" json:"REGION_DOMAIN_PREFIX"`
	NodeName           string    `gorm:"column:node_name;type:char(64);default:null" json:"NODE_NAME"`
	PodIP              string    `gorm:"column:pod_ip;type:char(64);default:null" json:"POD_IP"`
	PodName            string    `gorm:"column:pod_name;type:char(64);default:null" json:"POD_NAME"`
	CAMD5              string    `gorm:"column:ca_md5;type:char(64);default:null" json:"CA_MD5"`
	Lcuuid             string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

type AZControllerConnection struct {
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	AZ           string `gorm:"column:az;type:char(64);default:ALL" json:"AZ"`
	Region       string `gorm:"column:region;type:char(64);default:ffffffff-ffff-ffff-ffff-ffffffffffff" json:"REGION"`
	ControllerIP string `gorm:"column:controller_ip;type:char(64);default:null" json:"CONTROLLER_IP"`
	Lcuuid       string `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

func (AZControllerConnection) TableName() string {
	return "az_controller_connection"
}

type Analyzer struct {
	ID                int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	State             int       `gorm:"column:state;type:int;default:null" json:"STATE"`    // 0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception
	HaState           int       `gorm:"column:ha_state;type:int;default:1" json:"HA_STATE"` // 1.master 2.backup
	Name              string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	Description       string    `gorm:"column:description;type:varchar(256);default:null" json:"DESCRIPTION"`
	IP                string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	NATIP             string    `gorm:"column:nat_ip;type:char(64);default:null" json:"NAT_IP"`
	Agg               int       `gorm:"column:agg;type:int;default:1" json:"AGG"`
	CPUNum            int       `gorm:"column:cpu_num;type:int;default:0" json:"CPU_NUM"` // logical number of cpu
	MemorySize        int64     `gorm:"column:memory_size;type:bigint;default:0" json:"MEMORY_SIZE"`
	Arch              string    `gorm:"column:arch;type:varchar(256);default:null" json:"ARCH"`
	Os                string    `gorm:"column:os;type:varchar(256);default:null" json:"OS"`
	KernelVersion     string    `gorm:"column:kernel_version;type:varchar(256);default:null" json:"KERNEL_VERSION"`
	PcapDataMountPath string    `gorm:"column:pcap_data_mount_path;type:varchar(256);default:null" json:"PCAP_DATA_MOUNT_PATH"`
	VTapMax           int       `gorm:"column:vtap_max;type:int;default:200" json:"VTAP_MAX"`
	SyncedAt          time.Time `gorm:"column:synced_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"SYNCED_AT"`
	NATIPEnabled      int       `gorm:"column:nat_ip_enabled;default:0" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	PodIP             string    `gorm:"column:pod_ip;type:char(64);default:null" json:"POD_IP"`
	PodName           string    `gorm:"column:pod_name;type:char(64);default:null" json:"pod_name"`
	CAMD5             string    `gorm:"column:ca_md5;type:char(64);default:null" json:"CA_MD5"`
	Lcuuid            string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

type AZAnalyzerConnection struct {
	ID         int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	AZ         string `gorm:"column:az;type:char(64);default:ALL" json:"AZ"`
	Region     string `gorm:"column:region;type:char(64);default:ffffffff-ffff-ffff-ffff-ffffffffffff" json:"REGION"`
	AnalyzerIP string `gorm:"column:analyzer_ip;type:char(64);default:null" json:"ANALYZER_IP"`
	Lcuuid     string `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

func (AZAnalyzerConnection) TableName() string {
	return "az_analyzer_connection"
}

type VTap struct {
	ID                 int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name               string    `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	State              int       `gorm:"column:state;type:int;default:1" json:"STATE"`   // 0.not-connected 1.normal
	Enable             int       `gorm:"column:enable;type:int;default:1" json:"ENABLE"` // 0: stop 1: running
	Type               int       `gorm:"column:type;type:int;default:0" json:"TYPE"`     // 1: process 2: vm 3: public cloud 4: analyzer 5: physical machine 6: dedicated physical machine 7: host pod 8: vm pod
	CtrlIP             string    `gorm:"column:ctrl_ip;type:char(64);not null" json:"CTRL_IP"`
	CtrlMac            string    `gorm:"column:ctrl_mac;type:char(64);default:null" json:"CTRL_MAC"`
	TapMac             string    `gorm:"column:tap_mac;type:char(64);default:null" json:"TAP_MAC"`
	AnalyzerIP         string    `gorm:"column:analyzer_ip;type:char(64);not null" json:"ANALYZER_IP"`
	CurAnalyzerIP      string    `gorm:"column:cur_analyzer_ip;type:char(64);not null" json:"CUR_ANALYZER_IP"`
	ControllerIP       string    `gorm:"column:controller_ip;type:char(64);not null" json:"CONTROLLER_IP"`
	CurControllerIP    string    `gorm:"column:cur_controller_ip;type:char(64);not null" json:"CUR_CONTROLLER_IP"`
	LaunchServer       string    `gorm:"column:launch_server;type:char(64);not null" json:"LAUNCH_SERVER"`
	LaunchServerID     int       `gorm:"column:launch_server_id;type:int;default:null" json:"LAUNCH_SERVER_ID"`
	AZ                 string    `gorm:"column:az;type:char(64);default:''" json:"AZ"`
	Region             string    `gorm:"column:region;type:char(64);default:''" json:"REGION"`
	Revision           string    `gorm:"column:revision;type:varchar(256);default:null" json:"REVISION"`
	SyncedControllerAt time.Time `gorm:"column:synced_controller_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"SYNCED_CONTROLLER_AT"`
	SyncedAnalyzerAt   time.Time `gorm:"column:synced_analyzer_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"SYNCED_ANALYZER_AT"`
	CreatedAt          time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	BootTime           int       `gorm:"column:boot_time;type:int;default:0" json:"BOOT_TIME"`
	Exceptions         int64     `gorm:"column:exceptions;type:int unsigned;default:0" json:"EXCEPTIONS"`
	VTapLcuuid         string    `gorm:"column:vtap_lcuuid;type:char(64);default:null" json:"VTAP_LCUUID"`
	VtapGroupLcuuid    string    `gorm:"column:vtap_group_lcuuid;type:char(64);default:null" json:"VTAP_GROUP_LCUUID"`
	CPUNum             int       `gorm:"column:cpu_num;type:int;default:0" json:"CPU_NUM"` // logical number of cpu
	MemorySize         int64     `gorm:"column:memory_size;type:bigint;default:0" json:"MEMORY_SIZE"`
	Arch               string    `gorm:"column:arch;type:varchar(256);default:null" json:"ARCH"`
	Os                 string    `gorm:"column:os;type:varchar(256);default:null" json:"OS"`
	KernelVersion      string    `gorm:"column:kernel_version;type:varchar(256);default:null" json:"KERNEL_VERSION"`
	ProcessName        string    `gorm:"column:process_name;type:varchar(256);default:null" json:"PROCESS_NAME"`
	LicenseType        int       `gorm:"column:license_type;type:int;default:null" json:"LICENSE_TYPE"`   // 1: A类 2: B类 3: C类
	LicenseFunctions   string    `gorm:"column:license_functions;type:char(64)" json:"LICENSE_FUNCTIONS"` // separated by ,; 1: 流量分发 2: 网络监控 3: 应用监控
	TapMode            int       `gorm:"column:tap_mode;type:int;default:null" json:"TAP_MODE"`
	ExpectedRevision   string    `gorm:"column:expected_revision;type:text;default null" json:"EXPECTED_REVISION"`
	UpgradePackage     string    `gorm:"column:upgrade_package;type:text;default null" json:"UPGRADE_PACKAGE"`
	Lcuuid             string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
}

func (VTap) TableName() string {
	return "vtap"
}

type VTapGroup struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:varchar(64);not null" json:"NAME"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid    string    `gorm:"column:lcuuid;type:char(64);not null" json:"LCUUID"`
	ShortUUID string    `gorm:"column:short_uuid;type:char(32);default:null" json:"SHORT_UUID"`
}

func (VTapGroup) TableName() string {
	return "vtap_group"
}

type DataSource struct {
	ID                        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name                      string    `gorm:"column:name;type:char(64);default:''" json:"NAME"`
	TsdbType                  string    `gorm:"column:tsdb_type;type:char(64);default:''" json:"TSDB_TYPE"`
	State                     int       `gorm:"column:state;type:int;default:1" json:"STATE"`
	BaseDataSourceID          int       `gorm:"column:base_data_source_id;type:int" json:"BASE_DATA_SOURCE_ID"`
	Interval                  int       `gorm:"column:interval;type:int" json:"INTERVAL"`
	RetentionTime             int       `gorm:"column:retention_time;type:int" json:"RETENTION_TIME"` // unit: hour
	SummableMetricsOperator   string    `gorm:"column:summable_metrics_operator;type:char(64)" json:"SUMMABLE_METRICS_OPERATOR"`
	UnSummableMetricsOperator string    `gorm:"column:unsummable_metrics_operator;type:char(64)" json:"UNSUMMABLE_METRICS_OPERATOR"`
	UpdatedAt                 time.Time `gorm:"column:updated_at" json:"UPDATED_AT"`
	Lcuuid                    string    `gorm:"column:lcuuid;type:char(64)" json:"LCUUID"`
}

type VTapGroupConfiguration struct {
	ID                            int     `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MaxCollectPps                 *int    `gorm:"column:max_collect_pps;type:int;default:null" json:"MAX_COLLECT_PPS"`
	MaxNpbBps                     *int64  `gorm:"column:max_npb_bps;type:bigint;default:null" json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                       *int    `gorm:"column:max_cpus;type:int;default:null" json:"MAX_CPUS"`
	MaxMemory                     *int    `gorm:"column:max_memory;type:int;default:null" json:"MAX_MEMORY"` // unit: M
	SyncInterval                  *int    `gorm:"column:sync_interval;type:int;default:null" json:"SYNC_INTERVAL"`
	StatsInterval                 *int    `gorm:"column:stats_interval;type:int;default:null" json:"STATS_INTERVAL"`
	RsyslogEnabled                *int    `gorm:"column:rsyslog_enabled;type:tinyint(1);default:null" json:"RSYSLOG_ENABLED"` // 0: disabled 1:enabled
	MaxTxBandwidth                *int64  `gorm:"column:max_tx_bandwidth;type:bigint;default:null" json:"MAX_TX_BANDWIDTH"`   // unit: bps
	BandwidthProbeInterval        *int    `gorm:"column:bandwidth_probe_interval;type:int;default:null" json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex             *string `gorm:"column:tap_interface_regex;type:text;default:null" json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds              *int    `gorm:"column:max_escape_seconds;type:int;default:null" json:"MAX_ESCAPE_SECONDS"`
	Mtu                           *int    `gorm:"column:mtu;type:int;default:null" json:"MTU"`
	OutputVlan                    *int    `gorm:"column:output_vlan;type:int;default:null" json:"OUTPUT_VLAN"`
	CollectorSocketType           *string `gorm:"column:collector_socket_type;type:char(64);default:null" json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType          *string `gorm:"column:compressor_socket_type;type:char(64);default:null" json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                 *string `gorm:"column:npb_socket_type;type:char(64);default:null" json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                   *int    `gorm:"column:npb_vlan_mode;type:int;default:null" json:"NPB_VLAN_MODE"`
	CollectorEnabled              *int    `gorm:"column:collector_enabled;type:tinyint(1);default:null" json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled             *int    `gorm:"column:vtap_flow_1s_enabled;type:tinyint(1);default:null" json:"VTAP_FLOW_1S_ENABLED"` // 0: disabled 1:enabled
	L4LogTapTypes                 *string `gorm:"column:l4_log_tap_types;type:text;default:null" json:"L4_LOG_TAP_TYPES"`               // tap type info, separate by ","
	NpbDedupEnabled               *int    `gorm:"column:npb_dedup_enabled;type:tinyint(1);default:null" json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled               *int    `gorm:"column:platform_enabled;type:tinyint(1);default:null" json:"PLATFORM_ENABLED"`         // 0: disabled 1:enabled
	IfMacSource                   *int    `gorm:"column:if_mac_source;type:int;default:null" json:"IF_MAC_SOURCE"`                      // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     *string `gorm:"column:vm_xml_path;type:text;default:null" json:"VM_XML_PATH"`
	ExtraNetnsRegex               *string `gorm:"column:extra_netns_regex;type:text;default:null" json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                  *int    `gorm:"column:nat_ip_enabled;type:tinyint(1);default:null" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize             *int    `gorm:"column:capture_packet_size;type:int;default:null" json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled     *int    `gorm:"column:inactive_server_port_enabled;type:tinyint(1);default:null" json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled             *int    `gorm:"column:inactive_ip_enabled;type:tinyint(1);default:null" json:"INACTIVE_IP_ENABLED"`                   // 0: disabled 1:enabled
	VTapGroupLcuuid               *string `gorm:"column:vtap_group_lcuuid;type:char(64);default:null" json:"VTAP_GROUP_LCUUID"`
	LogThreshold                  *int    `gorm:"column:log_threshold;type:int;default:null" json:"LOG_THRESHOLD"`
	LogLevel                      *string `gorm:"column:log_level;type:char(64);default:null" json:"LOG_LEVEL"`
	LogRetention                  *int    `gorm:"column:log_retention;type:int;default:null" json:"LOG_RETENTION"`
	HTTPLogProxyClient            *string `gorm:"column:http_log_proxy_client;type:char(64);default:null" json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                *string `gorm:"column:http_log_trace_id;type:text;default:null" json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize               *int    `gorm:"column:l7_log_packet_size;type:int;default:null" json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold      *int    `gorm:"column:l4_log_collect_nps_threshold;type:int;default:null" json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold      *int    `gorm:"column:l7_log_collect_nps_threshold;type:int;default:null" json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled              *int    `gorm:"column:l7_metrics_enabled;type:tinyint(1);default:null" json:"L7_METRICS_ENABLED"`   // 0: disabled 1:enabled
	L7LogStoreTapTypes            *string `gorm:"column:l7_log_store_tap_types;type:text;default:null" json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType             *int    `gorm:"column:capture_socket_type;type:int;default:null" json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                    *string `gorm:"column:capture_bpf;type:varchar(512);default:null" json:"CAPTURE_BPF"`
	TapMode                       *int    `gorm:"column:tap_mode;type:int;default:null" json:"TAP_MODE"` // 0: local 1: mirror 2: physical
	ThreadThreshold               *int    `gorm:"column:thread_threshold;type:int;default:null" json:"THREAD_THRESHOLD"`
	ProcessThreshold              *int    `gorm:"column:process_threshold;type:int;default:null" json:"PROCESS_THRESHOLD"`
	Lcuuid                        *string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	NtpEnabled                    *int    `gorm:"column:ntp_enabled;type:tinyint(1);default:null" json:"NTP_ENABLED"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled          *int    `gorm:"column:l4_performance_enabled;type:tinyint(1);default:null" json:"L4_PERFORMANCE_ENABLED"`   // 0: disabled 1:enabled
	PodClusterInternalIP          *int    `gorm:"column:pod_cluster_internal_ip;type:tinyint(1);default:null" json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                       *string `gorm:"column:domains;type:text;default:null" json:"DOMAINS"`                                       // domains info, separate by ","
	DecapType                     *string `gorm:"column:decap_type;type:text;default:null" json:"DECAP_TYPE"`                                 // separate by ","
	HTTPLogSpanID                 *string `gorm:"column:http_log_span_id;type:text;default:null" json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit            *int    `gorm:"column:sys_free_memory_limit;type:int;default:null" json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                   *int    `gorm:"column:log_file_size;type:int;default:null" json:"LOG_FILE_SIZE"`                 // unit: MB
	HTTPLogXRequestID             *string `gorm:"column:http_log_x_request_id;type:char(64);default:null" json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled *int    `gorm:"column:external_agent_http_proxy_enabled;type:tinyint(1);default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort    *int    `gorm:"column:external_agent_http_proxy_port;type:int;default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	AnalyzerPort                  *int    `gorm:"column:analyzer_port;type:int;default:null" json:"ANALYZER_PORT"`
	ProxyControllerPort           *int    `gorm:"column:proxy_controller_port;type:int;default:null" json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP             *string `gorm:"column:proxy_controller_ip;type:varchar(512);default:null" json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                    *string `gorm:"column:analyzer_ip;type:varchar(512);default:null" json:"ANALYZER_IP"`
	YamlConfig                    *string `gorm:"column:yaml_config;type:text;default:null" json:"YAML_CONFIG"`
}

func (VTapGroupConfiguration) TableName() string {
	return "vtap_group_configuration"
}

// VtapGroupConfiguration [...]
type RVTapGroupConfiguration struct {
	ID                            int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MaxCollectPps                 int    `gorm:"column:max_collect_pps;type:int;default:null" json:"MAX_COLLECT_PPS"`
	MaxNpbBps                     int64  `gorm:"column:max_npb_bps;type:bigint;default:null" json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                       int    `gorm:"column:max_cpus;type:int;default:null" json:"MAX_CPUS"`
	MaxMemory                     int    `gorm:"column:max_memory;type:int;default:null" json:"MAX_MEMORY"` // unit: M
	SyncInterval                  int    `gorm:"column:sync_interval;type:int;default:null" json:"SYNC_INTERVAL"`
	StatsInterval                 int    `gorm:"column:stats_interval;type:int;default:null" json:"STATS_INTERVAL"`
	RsyslogEnabled                int    `gorm:"column:rsyslog_enabled;type:tinyint(1);default:null" json:"RSYSLOG_ENABLED"` // 0: disabled 1:enabled
	MaxTxBandwidth                int64  `gorm:"column:max_tx_bandwidth;type:bigint;default:null" json:"MAX_TX_BANDWIDTH"`   // unit: bps
	BandwidthProbeInterval        int    `gorm:"column:bandwidth_probe_interval;type:int;default:null" json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex             string `gorm:"column:tap_interface_regex;type:text;default:null" json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds              int    `gorm:"column:max_escape_seconds;type:int;default:null" json:"MAX_ESCAPE_SECONDS"`
	Mtu                           int    `gorm:"column:mtu;type:int;default:null" json:"MTU"`
	OutputVlan                    int    `gorm:"column:output_vlan;type:int;default:null" json:"OUTPUT_VLAN"`
	CollectorSocketType           string `gorm:"column:collector_socket_type;type:char(64);default:null" json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType          string `gorm:"column:compressor_socket_type;type:char(64);default:null" json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                 string `gorm:"column:npb_socket_type;type:char(64);default:null" json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                   int    `gorm:"column:npb_vlan_mode;type:int;default:null" json:"NPB_VLAN_MODE"`
	CollectorEnabled              int    `gorm:"column:collector_enabled;type:tinyint(1);default:null" json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled             int    `gorm:"column:vtap_flow_1s_enabled;type:tinyint(1);default:null" json:"VTAP_FLOW_1S_ENABLED"` // 0: disabled 1:enabled
	L4LogTapTypes                 string `gorm:"column:l4_log_tap_types;type:text;default:null" json:"L4_LOG_TAP_TYPES"`               // tap type info, separate by ","
	NpbDedupEnabled               int    `gorm:"column:npb_dedup_enabled;type:tinyint(1);default:null" json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled               int    `gorm:"column:platform_enabled;type:tinyint(1);default:null" json:"PLATFORM_ENABLED"`         // 0: disabled 1:enabled
	IfMacSource                   int    `gorm:"column:if_mac_source;type:int;default:null" json:"IF_MAC_SOURCE"`                      // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     string `gorm:"column:vm_xml_path;type:text;default:null" json:"VM_XML_PATH"`
	ExtraNetnsRegex               string `gorm:"column:extra_netns_regex;type:text;default:null" json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                  int    `gorm:"column:nat_ip_enabled;type:tinyint(1);default:null" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize             int    `gorm:"column:capture_packet_size;type:int;default:null" json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled     int    `gorm:"column:inactive_server_port_enabled;type:tinyint(1);default:null" json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled             int    `gorm:"column:inactive_ip_enabled;type:tinyint(1);default:null" json:"INACTIVE_IP_ENABLED"`                   // 0: disabled 1:enabled
	VTapGroupLcuuid               string `gorm:"column:vtap_group_lcuuid;type:char(64);default:null" json:"VTAP_GROUP_LCUUID"`
	LogThreshold                  int    `gorm:"column:log_threshold;type:int;default:null" json:"LOG_THRESHOLD"`
	LogLevel                      string `gorm:"column:log_level;type:char(64);default:null" json:"LOG_LEVEL"`
	LogRetention                  int    `gorm:"column:log_retention;type:int;default:null" json:"LOG_RETENTION"`
	HTTPLogProxyClient            string `gorm:"column:http_log_proxy_client;type:char(64);default:null" json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                string `gorm:"column:http_log_trace_id;type:text;default:null" json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize               int    `gorm:"column:l7_log_packet_size;type:int;default:null" json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold      int    `gorm:"column:l4_log_collect_nps_threshold;type:int;default:null" json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold      int    `gorm:"column:l7_log_collect_nps_threshold;type:int;default:null" json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled              int    `gorm:"column:l7_metrics_enabled;type:tinyint(1);default:null" json:"L7_METRICS_ENABLED"`   // 0: disabled 1:enabled
	L7LogStoreTapTypes            string `gorm:"column:l7_log_store_tap_types;type:text;default:null" json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType             int    `gorm:"column:capture_socket_type;type:int;default:null" json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                    string `gorm:"column:capture_bpf;type:varchar(512);default:null" json:"CAPTURE_BPF"`
	TapMode                       int    `gorm:"column:tap_mode;type:int;default:null" json:"TAP_MODE"` // 0: local 1: mirror 2: physical
	ThreadThreshold               int    `gorm:"column:thread_threshold;type:int;default:null" json:"THREAD_THRESHOLD"`
	ProcessThreshold              int    `gorm:"column:process_threshold;type:int;default:null" json:"PROCESS_THRESHOLD"`
	Lcuuid                        string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	NtpEnabled                    int    `gorm:"column:ntp_enabled;type:tinyint(1);default:null" json:"NTP_ENABLED"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled          int    `gorm:"column:l4_performance_enabled;type:tinyint(1);default:null" json:"L4_PERFORMANCE_ENABLED"`   // 0: disabled 1:enabled
	PodClusterInternalIP          int    `gorm:"column:pod_cluster_internal_ip;type:tinyint(1);default:null" json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                       string `gorm:"column:domains;type:text;default:null" json:"DOMAINS"`                                       // domains info, separate by ","
	DecapType                     string `gorm:"column:decap_type;type:text;default:null" json:"DECAP_TYPE"`                                 // separate by ","
	HTTPLogSpanID                 string `gorm:"column:http_log_span_id;type:text;default:null" json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit            int    `gorm:"column:sys_free_memory_limit;type:int;default:null" json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                   int    `gorm:"column:log_file_size;type:int;default:null" json:"LOG_FILE_SIZE"`                 // unit: MB
	HTTPLogXRequestID             string `gorm:"column:http_log_x_request_id;type:char(64);default:null" json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled int    `gorm:"column:external_agent_http_proxy_enabled;type:tinyint(1);default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort    int    `gorm:"column:external_agent_http_proxy_port;type:int;default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	AnalyzerPort                  int    `gorm:"column:analyzer_port;type:int;default:null" json:"ANALYZER_PORT"`
	ProxyControllerPort           int    `gorm:"column:proxy_controller_port;type:int;default:null" json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP             string `gorm:"column:proxy_controller_ip;type:varchar(512);default:null" json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                    string `gorm:"column:analyzer_ip;type:varchar(512);default:null" json:"ANALYZER_IP"`
	YamlConfig                    string `gorm:"column:yaml_config;type:text;default:null" json:"yaml_config"`
}

// SysConfiguration [...]
type SysConfiguration struct {
	ID        int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	ParamName string `gorm:"column:param_name;type:char(64);not null" json:"PARAM_NAME"`
	Value     string `gorm:"column:value;type:varchar(256);default:null" json:"VALUE"`
	Comments  string `gorm:"column:comments;type:text;default:null" json:"COMMENTS"`
	Lcuuid    string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
}

type KubernetesCluster struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	ClusterID string    `gorm:"column:cluster_id;type:varchar(256);" json:"CLUSTER_ID"`
	Value     string    `gorm:"column:value;type:varchar(256);" json:"VALUE"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	SyncedAt  time.Time `gorm:"column:synced_at" json:"SYNCED_AT"`
}

type GoGenesisVInterface struct {
	ID                  int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid              string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name                string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	MAC                 string    `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	IPS                 string    `gorm:"column:ips;type:text" json:"IPS"`
	TapName             string    `gorm:"column:tap_name;type:char(64);default:null" json:"TAP_NAME"`
	TapMAC              string    `gorm:"column:tap_mac;type:char(32);default:null" json:"TAP_MAC"`
	DeviceLcuuid        string    `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	DeviceName          string    `gorm:"column:device_name;type:char(512);default:null" json:"DEVICE_NAME"`
	DeviceType          string    `gorm:"column:device_type;type:char(64);default:null" json:"DEVICE_TYPE"`
	HostIP              string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	NodeIP              string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	VTapID              int       `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	LastSeen            time.Time `gorm:"column:last_seen;type:datetime;default:NULL" json:"LAST_SEEN"`
	KubernetesClusterID string    `gorm:"column:kubernetes_cluster_id;type:char(64);default:null" json:"KUBERNETES_CLUSTER_ID"`
}

func (GoGenesisVInterface) TableName() string {
	return "go_genesis_vinterface"
}

type ACL struct {
	ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	BusinessID   int       `gorm:"column:business_id;type:int;not null" json:"BUSINESS_ID"`
	Name         string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	Type         int       `gorm:"column:type;type:int;default:null;default:2" json:"TYPE"`         // 1-epc; 2-custom
	TapType      int       `gorm:"column:tap_type;type:int;default:null;default:3" json:"TAP_TYPE"` // 1-WAN; 3-LAN
	State        int       `gorm:"column:state;type:int;default:null;default:1" json:"STATE"`       // 0-disable; 1-enable
	Applications string    `gorm:"column:applications;type:char(64);not null" json:"APPLICATIONS"`  // separated by , (1-performance analysis; 2-backpacking; 6-npb)
	EpcID        int       `gorm:"column:epc_id;type:int;default:null" json:"EPC_ID"`
	SrcGroupIDs  string    `gorm:"column:src_group_ids;type:text;default:null" json:"SRC_GROUP_IDS"` // separated by ,
	DstGroupIDs  string    `gorm:"column:dst_group_ids;type:text;default:null" json:"DST_GROUP_IDS"` // separated by ,
	Protocol     *int      `gorm:"column:protocol;type:int;default:null" json:"PROTOCOL"`
	SrcPorts     string    `gorm:"column:src_ports;type:text;default:null" json:"SRC_PORTS"` // separated by ,
	DstPorts     string    `gorm:"column:dst_ports;type:text;default:null" json:"DST_PORTS"` // separated by ,
	Vlan         int       `gorm:"column:vlan;type:int;default:null" json:"VLAN"`
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid       string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
}

func (ACL) TableName() string {
	return "acl"
}

// ResourceGroupExtraInfo [...]
type ResourceGroupExtraInfo struct {
	ID           int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	ResourceType int    `gorm:"column:resource_type;type:int;not null" json:"RESOURCE_TYPE"` // 1: epc, 2: vm, 3: pod_group, 4: pod_service
	ResourceID   int    `gorm:"column:resource_id;type:int;not null" json:"RESOURCE_ID"`
	ResourceName string `gorm:"column:resource_name;type:char(64);not null" json:"RESOURCE_NAME"`
}

func (ResourceGroupExtraInfo) TableName() string {
	return "resource_group_extra_info"
}

// NpbPolicy [...]
type NpbPolicy struct {
	ID               int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name             string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	State            int       `gorm:"column:state;type:int;default:null;default:1" json:"STATE"` // 0-disable; 1-enable
	BusinessID       int       `gorm:"column:business_id;type:int;not null" json:"BUSINESS_ID"`
	Direction        int       `gorm:"column:direction;type:int;default:1" json:"DIRECTION"` // 1-two way; 2-server to client; 3-client to server
	Vni              int       `gorm:"column:vni;type:int;default:null" json:"VNI"`
	NpbTunnelID      int       `gorm:"column:npb_tunnel_id;type:int;default:null" json:"NPB_TUNNEL_ID"`
	Distribute       int       `gorm:"column:distribute;type:int;default:null" json:"distribute"` // 0-drop, 1-distribute
	PayloadSlice     *int      `gorm:"column:payload_slice;type:int;default:null" json:"PAYLOAD_SLICE"`
	ACLID            int       `gorm:"column:acl_id;type:int;default:null" json:"ACL_ID"`
	PolicyACLGroupID int       `gorm:"column:policy_acl_group_id;type:int;default:null" json:"POLICY_ACL_GROUP_ID"`
	VtapIDs          string    `gorm:"column:vtap_ids;type:text;default:null" json:"VTAP_IDS"` // separated by ,
	CreatedAt        time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt        time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid           string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
}

func (NpbPolicy) TableName() string {
	return "npb_policy"
}

// NpbTunnel [...]
type NpbTunnel struct {
	ID        int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string    `gorm:"column:name;type:char(64);not null" json:"NAME"`
	IP        string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Type      int       `gorm:"column:type;type:int;default:null" json:"TYPE"` // (0-VXLAN；1-ERSPAN)
	CreatedAt time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid    string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
}

func (NpbTunnel) TableName() string {
	return "npb_tunnel"
}

// PcapPolicy [...]
type PcapPolicy struct {
	ID               int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name             string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	State            int       `gorm:"column:state;type:int;default:null;default:1" json:"STATE"` // 0-disable; 1-enable
	BusinessID       int       `gorm:"column:business_id;type:int;not null" json:"BUSINESS_ID"`
	ACLID            int       `gorm:"column:acl_id;type:int;default:null" json:"ACL_ID"`
	VtapIDs          string    `gorm:"column:vtap_ids;type:text;default:null" json:"VTAP_IDS"` // separated by ,
	PayloadSlice     *int      `gorm:"column:payload_slice;type:int;default:null" json:"PAYLOAD_SLICE"`
	PolicyACLGroupID int       `gorm:"column:policy_acl_group_id;type:int;default:null" json:"POLICY_ACL_GROUP_ID"`
	UserID           int       `gorm:"column:user_id;type:int;default:null" json:"USER_ID"`
	CreatedAt        time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt        time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
	Lcuuid           string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
}

func (PcapPolicy) TableName() string {
	return "pcap_policy"
}

type DialTestTask struct {
	ID            int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name          string    `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	Protocol      int       `gorm:"column:protocol;type:int;not null" json:"PROTOCOL"` // 1.ICMP
	Host          string    `gorm:"column:host;type:varchar(256);not null" json:"HOST"`
	OvertimeTime  int       `gorm:"column:overtime_time;type:int;default:2000" json:"OVERTIME_TIME"`
	Payload       int       `gorm:"column:payload;type:int;default:64" json:"PAYLOAD"`
	TTL           int       `gorm:"column:ttl;type:smallint;default:64" json:"TTL"`
	DialLocation  string    `gorm:"column:dial_location;type:varchar(256);not null" json:"DIAL_LOCATION"`
	DialFrequency int       `gorm:"column:dial_frequency;type:int;default:1000" json:"DIAL_FREQUENCY"`
	PCAP          []byte    `gorm:"column:pcap;type:mediumblob" json:"PCAP"`
	CreatedAt     time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt     time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

func (DialTestTask) TableName() string {
	return "dial_test_task"
}

type VTapRepo struct {
	ID        int             `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string          `gorm:"column:name;type:char(64);not null" json:"NAME"`
	Arch      string          `gorm:"column:arch;type:varchar(256);default:''" json:"ARCH"`
	OS        string          `gorm:"column:os;type:varchar(256);default:''" json:"OS"`
	Branch    string          `gorm:"column:branch;type:varchar(256);default:''" json:"BRANCH"`
	RevCount  string          `gorm:"column:rev_count;type:varchar(256);default:''" json:"REV_COUNT"`
	CommitID  string          `gorm:"column:commit_id;type:varchar(256);default:''" json:"COMMIT_ID"`
	Image     compressedBytes `gorm:"column:image;type:logblob;not null" json:"IMAGE"`
	CreatedAt time.Time       `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt time.Time       `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

type compressedBytes []byte

// Scan scan decompress value into compressedBytes, implements sql.Scanner interface
func (c *compressedBytes) Scan(value interface{}) error {
	// decompress
	compressedData, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("failed to decompress compressedImage value:", value))
	}

	var b bytes.Buffer
	b.Write(compressedData)
	r, err := zlib.NewReader(&b)
	if err != nil {
		return err
	}
	defer r.Close()

	originData, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	*c = originData
	return nil
}

// Value return compress value, implement driver.Valuer interface
func (c compressedBytes) Value() (driver.Value, error) {
	// compress
	t1 := time.Now()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err := w.Write(c)
	if err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %v", err)
	}
	if err = w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib writer: %v", err)
	}
	log.Info("compress time comsumed: %v", time.Since(t1))
	return b.String(), nil
}

func (VTapRepo) TableName() string {
	return "vtap_repo"
}

type Plugin struct {
	ID        int             `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name      string          `gorm:"column:name;type:varchar(256);not null" json:"NAME"`
	Type      int             `gorm:"column:type;type:int" json:"TYPE"` // 1: wasm
	Image     compressedBytes `gorm:"column:image;type:logblob;not null" json:"IMAGE"`
	CreatedAt time.Time       `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
	UpdatedAt time.Time       `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"UPDATED_AT"`
}

func (Plugin) TableName() string {
	return "plugin"
}
