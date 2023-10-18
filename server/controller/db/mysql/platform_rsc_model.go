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

package mysql

import (
	"time"

	"gorm.io/gorm"
)

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

type Base struct {
	ID     int    `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null" mapstructure:"ID"`
	Lcuuid string `gorm:"unique;column:lcuuid;type:char(64)" mapstructure:"LCUUID"`
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
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at;type:datetime" mapstructure:"CREATED_AT"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;column:updated_at;type:datetime" mapstructure:"UPDATED_AT"`
}

type SoftDeleteBase struct {
	OperatedTime `mapstructure:",squash"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at;type:datetime;default:null" mapstructure:"DELETED_AT"`
}

type Process struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string    `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	VTapID         uint32    `gorm:"column:vtap_id;type:int;not null;default:0" mapstructure:"VTAP_ID"`
	PID            uint64    `gorm:"column:pid;type:int;not null;default:0" mapstructure:"PID"`
	ProcessName    string    `gorm:"column:process_name;type:varchar(256);default:''" mapstructure:"PROCESS_NAME"`
	CommandLine    string    `gorm:"column:command_line;type:text" mapstructure:"COMMAND_LINE"`
	UserName       string    `gorm:"column:user_name;type:varchar(256);default:''" mapstructure:"USER_NAME"`
	StartTime      time.Time `gorm:"autoCreateTime;column:start_time;type:datetime" mapstructure:"START_TIME"`
	OSAPPTags      string    `gorm:"column:os_app_tags;type:text" mapstructure:"OS_APP_TAGS"`
	ContainerID    string    `gorm:"column:container_id;type:char(64);default:''" mapstructure:"CONTAINER_ID"`
	NetnsID        uint32    `gorm:"column:netns_id;type:int unsigned;default:0" mapstructure:"NETNS_ID"` // used to associate processes with cloud and container resources
	SubDomain      string    `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string    `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
}

type Domain struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	OperatedTime `gorm:"embedded" mapstructure:",squash"`
	SyncedAt     *time.Time `gorm:"column:synced_at" mapstructure:"SYNCED_AT"`
	Name         string     `gorm:"column:name;type:varchar(64)" mapstructure:"NAME"`
	IconID       int        `gorm:"column:icon_id;type:int" mapstructure:"ICON_ID"`
	DisplayName  string     `gorm:"column:display_name;type:varchar(64);default:''" mapstructure:"DISPLAY_NAME"`
	ClusterID    string     `gorm:"column:cluster_id;type:char(64)" mapstructure:"CLUSTER_ID"`
	Type         int        `gorm:"column:type;type:int;default:0" mapstructure:"TYPE"` // 1.openstack 2.vsphere 3.nsp 4.tencent 5.filereader 6.aws 7.pingan 8.zstack 9.aliyun 10.huawei prv 11.k8s 12.simulation 13.huawei 14.qingcloud 15.qingcloud_private 16.F5 17.CMB_CMDB 18.azure 19.apsara_stack 20.tencent_tce 21.qingcloud_k8s 22.kingsoft_private 23.genesis 24.microsoft_acs 25.baidu_bce
	Config       string     `gorm:"column:config;type:text" mapstructure:"CONFIG"`
	ErrorMsg     string     `gorm:"column:error_msg;type:text" mapstructure:"ERROR_MSG"`
	Enabled      int        `gorm:"column:enabled;type:int;not null;default:1" mapstructure:"ENABLED"` // 0.false 1.true
	State        int        `gorm:"column:state;type:int;not null;default:1" mapstructure:"STATE"`     // 1.normal 2.deleting 3.exception
	ControllerIP string     `gorm:"column:controller_ip;type:char(64)" mapstructure:"CONTROLLER_IP"`
}

// TODO 最终可以与cloud模块命名统一，Domain -> DomainLcuuid

type SubDomain struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	OperatedTime `gorm:"embedded" mapstructure:",squash"`
	SyncedAt     *time.Time `gorm:"column:synced_at" mapstructure:"SYNCED_AT"`
	Domain       string     `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	Name         string     `gorm:"column:name;type:varchar(64);default:''" mapstructure:"NAME"`
	DisplayName  string     `gorm:"column:display_name;type:varchar(64);default:''" mapstructure:"DISPLAY_NAME"`
	CreateMethod int        `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	ClusterID    string     `gorm:"column:cluster_id;type:char(64);default:''" mapstructure:"CLUSTER_ID"`
	Config       string     `gorm:"column:config;type:text;default:''" mapstructure:"CONFIG"`
	ErrorMsg     string     `gorm:"column:error_msg;type:text;default:''" mapstructure:"ERROR_MSG"`
	Enabled      int        `gorm:"column:enabled;type:int;not null;default:1" mapstructure:"ENABLED"` // 0.false 1.true
	State        int        `gorm:"column:state;type:int;not null;default:1" mapstructure:"STATE"`     // 1.normal 2.deleting 3.exception
}

type Region struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string  `gorm:"column:name;type:varchar(64);default:''" mapstructure:"NAME"`
	CreateMethod   int     `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string  `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	Longitude      float64 `gorm:"column:longitude;type:double(7,4);default:null" mapstructure:"LONGITUDE"`
	Latitude       float64 `gorm:"column:latitude;type:double(7,4);default:null" mapstructure:"LATITUDE"`
}

type AZ struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(64);default:''" mapstructure:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
}

func (AZ) TableName() string {
	return "az"
}

type Host struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Type           int       `gorm:"column:type;type:int" mapstructure:"TYPE"`   // 1.Server 3.Gateway 4.DFI
	State          int       `gorm:"column:state;type:int" mapstructure:"STATE"` // 0.Temp 1.Creating 2.Complete 3.Modifying 4.Exception
	Name           string    `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string    `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Description    string    `gorm:"column:description;type:varchar(256);default:''" mapstructure:"DESCRIPTION"`
	IP             string    `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	HType          int       `gorm:"column:htype;type:int" mapstructure:"HTYPE"`                           // 1. Xen host 2. VMware host 3. KVM host 4. Public cloud host 5. Hyper-V
	CreateMethod   int       `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	UserName       string    `gorm:"column:user_name;type:varchar(64);default:''" mapstructure:"USER_NAME"`
	UserPasswd     string    `gorm:"column:user_passwd;type:varchar(64);default:''" mapstructure:"USER_PASSWD"`
	VCPUNum        int       `gorm:"column:vcpu_num;type:int;default:0" mapstructure:"VCPU_NUM"`
	MemTotal       int       `gorm:"column:mem_total;type:int;default:0" mapstructure:"MEM_TOTAL"` // unit: M
	AZ             string    `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string    `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	Domain         string    `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	SyncedAt       time.Time `gorm:"column:synced_at;type:datetime;not null;default:CURRENT_TIMESTAMP" mapstructure:"SYNCED_AT"`
	ExtraInfo      string    `gorm:"column:extra_info;type:text;default:''" mapstructure:"EXTRA_INFO"`
}

func (Host) TableName() string {
	return "host_device"
}

type VM struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	State          int    `gorm:"index:state_server_index;column:state;type:int;not null" mapstructure:"STATE"` // 0.Temp 1.Creating 2.Created 3.To run 4.Running 5.To suspend 6.Suspended 7.To resume 8. To stop 9.Stopped 10.Modifing 11.Exception 12.Destroying
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	HType          int    `gorm:"column:htype;type:int;default:1" mapstructure:"HTYPE"`                 // 1.vm-c 2.bm-c 3.vm-n 4.bm-n 5.vm-s 6.bm-s
	LaunchServer   string `gorm:"index:state_server_index;column:launch_server;type:char(64);default:''" mapstructure:"LAUNCH_SERVER"`
	CloudTags      string `gorm:"column:cloud_tags;type:text;default:''" mapstructure:"CLOUD_TAGS"` // separated by ,
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

func (VM) TableName() string {
	return "vm"
}

type VMPodNodeConnection struct {
	Base      `gorm:"embedded" mapstructure:",squash"`
	VMID      int    `gorm:"column:vm_id;type:int;default:null" mapstructure:"VM_ID"`
	PodNodeID int    `gorm:"column:pod_node_id;type:int;default:null" mapstructure:"POD_NODE_ID"`
	Domain    string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	SubDomain string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

func (VMPodNodeConnection) TableName() string {
	return "vm_pod_node_connection"
}

type VMSecurityGroup struct {
	Base            `gorm:"embedded" mapstructure:",squash"`
	SecurityGroupID int `gorm:"column:sg_id;type:int;not null" mapstructure:"SG_ID"`
	VMID            int `gorm:"column:vm_id;type:int;not null" mapstructure:"VM_ID"`
	Priority        int `gorm:"column:priority;type:int;not null" mapstructure:"PRIORITY"`
}

func (VMSecurityGroup) TableName() string {
	return "vm_security_group"
}

type Contact struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	Name         string    `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Mobile       string    `gorm:"column:mobile;type:char(13);default:''" mapstructure:"MOBILE"`
	Email        string    `gorm:"column:email;type:varchar(128);default:''" mapstructure:"EMAIL"`
	Company      string    `gorm:"column:company;type:varchar(128);default:''" mapstructure:"COMPANY"`
	PushEmail    string    `gorm:"column:push_email;type:text;default:null" mapstructure:"PUSH_EMAIL"`
	Domain       string    `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	AlarmPush    int       `gorm:"column:alarm_push;type:int;default:0" mapstructure:"ALARM_PUSH"`
	ReportPush   int       `gorm:"column:report_push;type:int;default:0" mapstructure:"REPORT_PUSH"`
	Deleted      int       `gorm:"column:deleted;type:int;default:0" mapstructure:"DELETED"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" mapstructure:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:datetime;default:null" mapstructure:"UPDATED_AT"`
}

type VPCContact struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	CreateMethod int `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	VPCID        int `gorm:"column:epc_id;type:int;default:0" mapstructure:"VPC_ID"`
	ContactID    int `gorm:"column:contact_id;type:int;default:0" mapstructure:"CONTACT_ID"`
}

func (VPCContact) TableName() string {
	return "epc_contact"
}

type VPC struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Domain         string `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"` // TODO delete in future
	TunnelID       int    `gorm:"column:tunnel_id;type:int;default:0" mapstructure:"TUNNEL_ID"`
	Mode           int    `gorm:"column:mode;type:int;default:2" mapstructure:"MODE"` //  1:route, 2:transparent
	CIDR           string `gorm:"column:cidr;type:char(64);default:''" mapstructure:"CIDR"`
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

func (VPC) TableName() string {
	return "epc"
}

type Network struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	State          int    `gorm:"column:state;type:int;not null" mapstructure:"STATE"`        // 0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.Destroyed
	NetType        int    `gorm:"column:net_type;type:int;default:4" mapstructure:"NET_TYPE"` // 1.CTRL 2.SERVICE 3.WAN 4.LAN
	Name           string `gorm:"column:name;type:varchar(256);not null" mapstructure:"NAME"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Label          string `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Description    string `gorm:"column:description;type:varchar(256);default:''" mapstructure:"DESCRIPTION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	ISP            int    `gorm:"column:isp;type:int;default:0" mapstructure:"ISP"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"VPC_ID"`
	SegmentationID int    `gorm:"column:segmentation_id;type:int;default:0" mapstructure:"SEGMENTATION_ID"`
	TunnelID       int    `gorm:"column:tunnel_id;type:int;default:0" mapstructure:"TUNNEL_ID"`
	Shared         bool   `gorm:"column:shared;type:int;default:0" mapstructure:"SHARED"`
	Topped         int    `gorm:"column:topped;type:int;default:0" mapstructure:"TOPPED"`
	IsVIP          int    `gorm:"column:is_vip;type:int;default:0" mapstructure:"IS_VIP"`
}

func (Network) TableName() string {
	return "vl2"
}

type Subnet struct {
	Base      `gorm:"embedded" mapstructure:",squash"`
	Prefix    string `gorm:"column:prefix;type:char(64);default:''" mapstructure:"PREFIX"`
	Netmask   string `gorm:"column:netmask;type:char(64);default:''" mapstructure:"NETMASK"`
	NetworkID int    `gorm:"column:vl2id;type:int;default:null" mapstructure:"VL2ID"`
	NetIndex  int    `gorm:"column:net_index;type:int;default:0" mapstructure:"NET_INDEX"`
	Name      string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label     string `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	SubDomain string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

func (Subnet) TableName() string {
	return "vl2_net"
}

type VRouter struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	State          int    `gorm:"index:state_server_index;column:state;type:int;not null" mapstructure:"STATE"` // 0.Temp 1.Creating 2.Created 3.Exception 4.Modifing 5.Destroying 6.To run 7.Running 8.To stop 9.Stopped
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	Description    string `gorm:"column:description;type:varchar(256);default:''" mapstructure:"DESCRIPTION"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	GWLaunchServer string `gorm:"index:state_server_index;column:gw_launch_server;type:char(64);default:''" mapstructure:"GW_LAUNCH_SERVER"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"` // TODO delete in future
}

func (VRouter) TableName() string {
	return "vnet"
}

type RoutingTable struct {
	Base        `gorm:"embedded" mapstructure:",squash"`
	VRouterID   int    `gorm:"column:vnet_id;type:int;default:null" mapstructure:"VNET_ID"`
	Destination string `gorm:"column:destination;type:text;default:''" mapstructure:"DESTINATION"`
	NexthopType string `gorm:"column:nexthop_type;type:text;default:''" mapstructure:"NEXTHOP_TYPE"`
	Nexthop     string `gorm:"column:nexthop;type:text;default:''" mapstructure:"NEXTHOP"`
}

type DHCPPort struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"VPC_ID"`
}

func (DHCPPort) TableName() string {
	return "dhcp_port"
}

type VInterface struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	Name         string    `gorm:"column:name;type:char(64);default:''" mapstructure:"NAME"`
	Index        int       `gorm:"column:ifindex;type:int;not null" mapstructure:"IFINDEX"`
	State        int       `gorm:"column:state;type:int;not null" mapstructure:"STATE"`                  // 1. Attached 2.Detached 3.Exception
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Type         int       `gorm:"column:iftype;type:int;default:0" mapstructure:"IFTYPE"`               // 0.Unknown 1.Control 2.Service 3.WAN 4.LAN 5.Trunk 6.Tap 7.Tool
	Mac          string    `gorm:"index:mac_index;column:mac;type:char(32);default:''" mapstructure:"MAC"`
	VMac         string    `gorm:"column:vmac;type:char(32);default:''" mapstructure:"VMAC"`
	TapMac       string    `gorm:"column:tap_mac;type:char(32);default:''" mapstructure:"TAP_MAC"`
	NetworkID    int       `gorm:"column:subnetid;type:int;default:0" mapstructure:"SUBNETID"` // vl2 id
	VlanTag      int       `gorm:"column:vlantag;type:int;default:0" mapstructure:"VLANTAG"`
	DeviceType   int       `gorm:"column:devicetype;type:int;default:null" mapstructure:"DEVICETYPE"`   // Type 0.unknown 1.vm 2.vgw 3.third-party-device 4.vmwaf 5.NSP-vgateway 6.host-device 7.network-device 9.DHCP-port 10.pod 11.pod_service 12. redis_instance 13. rds_instance 14. pod_node 15. load_balance 16. nat_gateway
	DeviceID     int       `gorm:"column:deviceid;type:int;default:null" mapstructure:"DEVICEID"`       // unknown: Senseless ID, vm: vm ID, vgw/NSP-vgateway: vnet ID, third-party-device: third_party_device ID, vmwaf: vmwaf ID, host-device: host_device ID, network-device: network_device ID
	NetnsID      uint32    `gorm:"column:netns_id;type:int unsigned;default:0" mapstructure:"NETNS_ID"` // used to associate processes with cloud and container resources
	VtapID       uint32    `gorm:"column:vtap_id;type:int;default:0" mapstructure:"VTAP_ID"`
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region       string    `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"UPDATED_AT"`
}

func (VInterface) TableName() string {
	return "vinterface"
}

type LANIP struct { // TODO 添加region字段
	Base         `gorm:"embedded" mapstructure:",squash"`
	IP           string    `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	Netmask      string    `gorm:"column:netmask;type:char(64);default:''" mapstructure:"NETMASK"`
	Gateway      string    `gorm:"column:gateway;type:char(64);default:''" mapstructure:"GATEWAY"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	NetworkID    int       `gorm:"column:vl2id;type:int;default:null" mapstructure:"VL2ID"`
	NetIndex     int       `gorm:"column:net_index;type:int;default:0" mapstructure:"NET_INDEX"`
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	VInterfaceID int       `gorm:"column:vifid;type:int;default:null" mapstructure:"VINTERFACE_ID"`
	SubnetID     int       `gorm:"column:vl2_net_id;type:int;default:0" mapstructure:"SUBNET_ID"`
	ISP          int       `gorm:"column:isp;type:int;default:0" mapstructure:"ISP"` // Used for multi-ISP access
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"UPDATED_AT"`
}

func (LANIP) TableName() string {
	return "vinterface_ip"
}

type WANIP struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	IP           string    `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	Alias        string    `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Netmask      int       `gorm:"column:netmask;type:int;default:null" mapstructure:"NETMASK"`
	Gateway      string    `gorm:"column:gateway;type:char(64);default:''" mapstructure:"GATEWAY"`
	CreateMethod int       `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	ISP          int       `gorm:"column:isp;type:int;default:null" mapstructure:"ISP"`
	VInterfaceID int       `gorm:"column:vifid;type:int;default:0" mapstructure:"VINTERFACE_ID"`
	SubnetID     int       `gorm:"column:vl2_net_id;type:int;default:0" mapstructure:"SUBNET_ID"`
	SubDomain    string    `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain       string    `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region       string    `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"CREATED_AT"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" mapstructure:"UPDATED_AT"`
}

func (WANIP) TableName() string {
	return "ip_resource"
}

type FloatingIP struct {
	Base      `gorm:"embedded" mapstructure:",squash"`
	Domain    string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region    string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	VPCID     int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"VPC_ID"`
	NetworkID int    `gorm:"column:vl2_id;type:int;default:null" mapstructure:"VL2_ID"` // TODO json字段是否能修改，需返回给前端？
	VMID      int    `gorm:"column:vm_id;type:int;default:null" mapstructure:"VM_ID"`
	IP        string `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
}

func (FloatingIP) TableName() string {
	return "floatingip"
}

type SecurityGroup struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:varchar(64);default:''" mapstructure:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	Topped         int    `gorm:"column:topped;type:int;default:0" mapstructure:"TOPPED"`
}

type SecurityGroupRule struct {
	Base            `gorm:"embedded" mapstructure:",squash"`
	SecurityGroupID int    `gorm:"column:sg_id;type:int;not null" mapstructure:"SG_ID"`
	Direction       int    `gorm:"column:direction;type:tinyint(1);not null;default:0" mapstructure:"DIRECTION"` // 0.Unknow 1.Ingress 2.Egress
	Protocol        string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	EtherType       int    `gorm:"column:ethertype;type:tinyint(1);not null;default:0" mapstructure:"ETHERTYPE"` // 0.Unknow 1.IPv4 2.IPv6
	LocalPortRange  string `gorm:"column:local_port_range;type:text;default:''" mapstructure:"LOCAL_PORT_RANGE"`
	RemotePortRange string `gorm:"column:remote_port_range;type:text;default:''" mapstructure:"REMOTE_PORT_RANGE"`
	Local           string `gorm:"column:local;type:text;default:''" mapstructure:"LOCAL"`
	Remote          string `gorm:"column:remote;type:text;default:''" mapstructure:"REMOTE"`
	Priority        int    `gorm:"column:priority;type:int;not null" mapstructure:"PRIORITY"`
	Action          int    `gorm:"column:action;type:tinyint(1);not null;default:0" mapstructure:"ACTION"` // 0.Unknow 1.Accept 2.Drop
}

type NATGateway struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	FloatingIPs    string `gorm:"column:floating_ips;type:text;default:''" mapstructure:"FLOATING_IPS"` // separated by ,
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"` // TODO delete in future
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

func (NATGateway) TableName() string {
	return "nat_gateway"
}

type NATRule struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	NATGatewayID   int    `gorm:"column:nat_id;type:int;default:0" mapstructure:"NAT_ID"`
	Type           string `gorm:"column:type;type:char(16);default:''" mapstructure:"TYPE"`
	Protocol       string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	FloatingIP     string `gorm:"column:floating_ip;type:char(64);default:''" mapstructure:"FLOATING_IP"`
	FloatingIPPort int    `gorm:"column:floating_ip_port;type:int;default:null" mapstructure:"FLOATING_IP_PORT"`
	FixedIP        string `gorm:"column:fixed_ip;type:char(64);default:''" mapstructure:"FIXED_IP"`
	FixedIPPort    int    `gorm:"column:fixed_ip_port;type:int;default:null" mapstructure:"FIXED_IP_PORT"`
	VInterfaceID   int    `gorm:"column:port_id;type:int;default:null" mapstructure:"PORT_ID"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (NATRule) TableName() string {
	return "nat_rule"
}

type NATVMConnection struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	NATGatewayID int    `gorm:"column:nat_id;type:int;default:null" mapstructure:"NAT_ID"`
	VMID         int    `gorm:"column:vm_id;type:int;default:null" mapstructure:"VM_ID"`
	Domain       string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (NATVMConnection) TableName() string {
	return "nat_vm_connection"
}

type LB struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	Model          int    `gorm:"column:model;type:int;default:0" mapstructure:"MODEL"` // 1.Internal 2.External
	VIP            string `gorm:"column:vip;type:text;default:''" mapstructure:"VIP"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"` // TODO delete in future
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

func (LB) TableName() string {
	return "lb"
}

type LBListener struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	LBID           int    `gorm:"column:lb_id;type:int;default:0" mapstructure:"LB_ID"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	IPs            string `gorm:"column:ips;type:text;default:''" mapstructure:"IPS"`           // separated by ,
	SNATIPs        string `gorm:"column:snat_ips;type:text;default:''" mapstructure:"SNAT_IPS"` // separated by ,
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	Port           int    `gorm:"column:port;type:int;default:null" mapstructure:"PORT"`
	Protocol       string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (LBListener) TableName() string {
	return "lb_listener"
}

type LBTargetServer struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	LBID         int    `gorm:"column:lb_id;type:int;default:0" mapstructure:"LB_ID"`
	LBListenerID int    `gorm:"column:lb_listener_id;type:int;default:0" mapstructure:"LB_LISTENER_ID"`
	VPCID        int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	Type         int    `gorm:"column:type;type:int;default:0" mapstructure:"TYPE"` // 1.VM 2.IP
	IP           string `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	VMID         int    `gorm:"column:vm_id;type:int;default:0" mapstructure:"VM_ID"`
	Port         int    `gorm:"column:port;type:int;default:null" mapstructure:"PORT"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	Domain       string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (LBTargetServer) TableName() string {
	return "lb_target_server"
}

type LBVMConnection struct {
	Base   `gorm:"embedded" mapstructure:",squash"`
	LBID   int    `gorm:"column:lb_id;type:int;default:null" mapstructure:"LB_ID"`
	VMID   int    `gorm:"column:vm_id;type:int;default:null" mapstructure:"VM_ID"`
	Domain string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (LBVMConnection) TableName() string {
	return "lb_vm_connection"
}

type PeerConnection struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	LocalVPCID     int    `gorm:"column:local_epc_id;type:int;default:0" mapstructure:"LOCAL_EPC_ID"`
	RemoteVPCID    int    `gorm:"column:remote_epc_id;type:int;default:0" mapstructure:"REMOTE_EPC_ID"`
	LocalRegionID  int    `gorm:"column:local_region_id;type:int;default:0" mapstructure:"LOCAL_REGION_ID"`
	RemoteRegionID int    `gorm:"column:remote_region_id;type:int;default:0" mapstructure:"REMOTE_REGION_ID"`
	CreateMethod   int    `gorm:"column:create_method;type:int;default:0" mapstructure:"CREATE_METHOD"` // 0.learning 1.user_defined
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type CEN struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	VPCIDs         string `gorm:"column:epc_ids;type:text;default:''" mapstructure:"EPC_IDS"` // separated by ,
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (CEN) TableName() string {
	return "cen"
}

type RDSInstance struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	State          int    `gorm:"column:state;type:tinyint(1);not null;default:0" mapstructure:"STATE"` // 0. Unknown 1. Running 2. Recovering
	Domain         string `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	Type           int    `gorm:"column:type;type:int;default:0" mapstructure:"TYPE"` // 0. Unknown 1. MySQL 2. SqlServer 3. PPAS 4. PostgreSQL 5. MariaDB
	Version        string `gorm:"column:version;type:char(64);default:''" mapstructure:"VERSION"`
	Series         int    `gorm:"column:series;type:tinyint(1);not null;default:0" mapstructure:"SERIES"` // 0. Unknown 1. basic 2. HA
	Model          int    `gorm:"column:model;type:tinyint(1);not null;default:0" mapstructure:"MODEL"`   // 0. Unknown 1. Primary 2. Readonly 3. Temporary 4. Disaster recovery 5. share
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

func (RDSInstance) TableName() string {
	return "rds_instance"
}

type RedisInstance struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label          string `gorm:"column:label;type:char(64);default:''" mapstructure:"LABEL"`
	State          int    `gorm:"column:state;type:tinyint(1);not null;default:0" mapstructure:"STATE"` // 0. Unknown 1. Running 2. Recovering
	Domain         string `gorm:"column:domain;type:char(64);default:''" mapstructure:"DOMAIN"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:0" mapstructure:"EPC_ID"`
	Version        string `gorm:"column:version;type:char(64);default:''" mapstructure:"VERSION"`
	InternalHost   string `gorm:"column:internal_host;type:varchar(128);default:''" mapstructure:"INTERNAL_HOST"`
	PublicHost     string `gorm:"column:public_host;type:varchar(128);default:''" mapstructure:"PUBLIC_HOST"`
	UID            string `gorm:"column:uid;type:char(64);default:''" mapstructure:"UID"`
}

type VIP struct {
	Base   `gorm:"embedded" mapstructure:",squash"`
	IP     string `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	Domain string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	VTapID uint32 `gorm:"column:vtap_id;type:int;not null;default:0" mapstructure:"VTAP_ID"`
}

func (VIP) TableName() string {
	return "vip"
}

type PodCluster struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	ClusterName    string `gorm:"column:cluster_name;type:varchar(256);default:''" mapstructure:"CLUSTER_NAME"`
	Version        string `gorm:"column:version;type:varchar(256);default:''" mapstructure:"VERSION"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:null" mapstructure:"VPC_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodNamespace struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	CloudTags      string `gorm:"column:cloud_tags;type:text;default:''" mapstructure:"CLOUD_TAGS"` // separated by ,
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodNode struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Type           int    `gorm:"column:type;type:int;default:null" mapstructure:"TYPE"`               // 1: Master 2: Node
	ServerType     int    `gorm:"column:server_type;type:int;default:null" mapstructure:"SERVER_TYPE"` // 1: Host 2: VM
	State          int    `gorm:"column:state;type:int;default:1" mapstructure:"STATE"`                // 0: Exception 1: Normal
	IP             string `gorm:"column:ip;type:char(64);default:''" mapstructure:"IP"`
	VCPUNum        int    `gorm:"column:vcpu_num;type:int;default:0" mapstructure:"VCPU_NUM"`
	MemTotal       int    `gorm:"column:mem_total;type:int;default:0" mapstructure:"MEM_TOTAL"` // unit: M
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	VPCID          int    `gorm:"column:epc_id;type:int;default:null" mapstructure:"VPC_ID"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodIngress struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" mapstructure:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodIngressRule struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	Host         string `gorm:"column:host;type:text;default:''" mapstructure:"HOST"`
	PodIngressID int    `gorm:"column:pod_ingress_id;type:int;default:null" mapstructure:"POD_INGRESS_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

type PodIngressRuleBackend struct {
	Base             `gorm:"embedded" mapstructure:",squash"`
	Path             string `gorm:"column:path;type:text;default:''" mapstructure:"PATH"`
	Port             int    `gorm:"column:port;type:int;default:null" mapstructure:"PORT"`
	PodServiceID     int    `gorm:"column:pod_service_id;type:int;default:null" mapstructure:"POD_SERVICE_ID"`
	PodIngressRuleID int    `gorm:"column:pod_ingress_rule_id;type:int;default:null" mapstructure:"POD_INGRESS_RULE_ID"`
	PodIngressID     int    `gorm:"column:pod_ingress_id;type:int;default:null" mapstructure:"POD_INGRESS_ID"`
	SubDomain        string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

type PodService struct {
	Base             `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase   `gorm:"embedded" mapstructure:",squash"`
	Name             string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Label            string `gorm:"column:label;type:text;default:''" mapstructure:"LABEL"`           // separated by ,
	Annotation       string `gorm:"column:annotation;type:text;default:''" mapstructure:"ANNOTATION"` // separated by ,
	Alias            string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Type             int    `gorm:"column:type;type:int;default:null" mapstructure:"TYPE"`        // 1: ClusterIP 2: NodePort
	Selector         string `gorm:"column:selector;type:text;default:''" mapstructure:"SELECTOR"` // separated by ,
	ServiceClusterIP string `gorm:"column:service_cluster_ip;type:char(64);default:''" mapstructure:"SERVICE_CLUSTER_IP"`
	PodIngressID     int    `gorm:"column:pod_ingress_id;type:int;default:null" mapstructure:"POD_INGRESS_ID"`
	PodNamespaceID   int    `gorm:"column:pod_namespace_id;type:int;default:null" mapstructure:"POD_NAMESPACE_ID"`
	PodClusterID     int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	VPCID            int    `gorm:"column:epc_id;type:int;default:null" mapstructure:"VPC_ID"`
	AZ               string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region           string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain        string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain           string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodServicePort struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	Port         int    `gorm:"column:port;type:int;default:null" mapstructure:"PORT"`
	TargetPort   int    `gorm:"column:target_port;type:int;default:null" mapstructure:"TARGET_PORT"`
	NodePort     int    `gorm:"column:node_port;type:int;default:null" mapstructure:"NODE_PORT"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" mapstructure:"POD_SERVICE_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

type PodGroup struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Type           int    `gorm:"column:type;type:int;default:null" mapstructure:"TYPE"` // 1: Deployment 2: StatefulSet 3: ReplicationController
	PodNum         int    `gorm:"column:pod_num;type:int;default:1" mapstructure:"POD_NUM"`
	Label          string `gorm:"column:label;type:text;default:''" mapstructure:"LABEL"` // separated by ,
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" mapstructure:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

type PodGroupPort struct {
	Base         `gorm:"embedded" mapstructure:",squash"`
	Name         string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Protocol     string `gorm:"column:protocol;type:char(64);default:''" mapstructure:"PROTOCOL"`
	Port         int    `gorm:"column:port;type:int;default:null" mapstructure:"PORT"`
	PodGroupID   int    `gorm:"column:pod_group_id;type:int;default:null" mapstructure:"POD_GROUP_ID"`
	PodServiceID int    `gorm:"column:pod_service_id;type:int;default:null" mapstructure:"POD_SERVICE_ID"`
	SubDomain    string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
}

type PodReplicaSet struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Name           string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias          string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	Label          string `gorm:"column:label;type:text;default:''" mapstructure:"LABEL"` // separated by ,
	PodNum         int    `gorm:"column:pod_num;type:int;default:1" mapstructure:"POD_NUM"`
	PodGroupID     int    `gorm:"column:pod_group_id;type:int;default:null" mapstructure:"POD_GROUP_ID"`
	PodNamespaceID int    `gorm:"column:pod_namespace_id;type:int;default:null" mapstructure:"POD_NAMESPACE_ID"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	AZ             string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region         string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}

func (PodReplicaSet) TableName() string {
	return "pod_rs"
}

type PrometheusTarget struct {
	Base           `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase `gorm:"embedded" mapstructure:",squash"`
	Instance       string `gorm:"column:instance;type:varchar(255);default:''" mapstructure:"INSTANCE"`
	Job            string `gorm:"column:job;type:varchar(255);default:''" mapstructure:"JOB"`
	ScrapeURL      string `gorm:"column:scrape_url;type:varchar(2083);default:''" mapstructure:"SCRAPE_URL"`
	OtherLabels    string `gorm:"column:other_labels;type:text;default:''" mapstructure:"OTHER_LABELS"` // separated by ,
	SubDomain      string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain         string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
	PodClusterID   int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	CreateMethod   int    `gorm:"column:create_method;type:tinyint(1);default:1" mapstructure:"CREATE_METHOD"`
}

func (PrometheusTarget) TableName() string {
	return "prometheus_target"
}

type Pod struct {
	Base            `gorm:"embedded" mapstructure:",squash"`
	SoftDeleteBase  `gorm:"embedded" mapstructure:",squash"`
	Name            string `gorm:"column:name;type:varchar(256);default:''" mapstructure:"NAME"`
	Alias           string `gorm:"column:alias;type:char(64);default:''" mapstructure:"ALIAS"`
	State           int    `gorm:"column:state;type:int;not null" mapstructure:"STATE"`                    // 0.Exception 1.Running
	Label           string `gorm:"column:label;type:text;default:''" mapstructure:"LABEL"`                 // separated by ,
	Annotation      string `gorm:"column:annotation;type:text;default:''" mapstructure:"ANNOTATION"`       // separated by ,
	ENV             string `gorm:"column:env;type:text;default:''" mapstructure:"ENV"`                     // separated by ,
	ContainerIDs    string `gorm:"column:container_ids;type:text;default:''" mapstructure:"CONTAINER_IDS"` // separated by ,
	PodReplicaSetID int    `gorm:"column:pod_rs_id;type:int;default:null" mapstructure:"POD_RS_ID"`
	PodGroupID      int    `gorm:"column:pod_group_id;type:int;default:null" mapstructure:"POD_GROUP_ID"`
	PodNamespaceID  int    `gorm:"column:pod_namespace_id;type:int;default:null" mapstructure:"POD_NAMESPACE_ID"`
	PodNodeID       int    `gorm:"column:pod_node_id;type:int;default:null" mapstructure:"POD_NODE_ID"`
	PodClusterID    int    `gorm:"column:pod_cluster_id;type:int;default:null" mapstructure:"POD_CLUSTER_ID"`
	VPCID           int    `gorm:"column:epc_id;type:int;default:null" mapstructure:"VPC_ID"`
	AZ              string `gorm:"column:az;type:char(64);default:''" mapstructure:"AZ"`
	Region          string `gorm:"column:region;type:char(64);default:''" mapstructure:"REGION"`
	SubDomain       string `gorm:"column:sub_domain;type:char(64);default:''" mapstructure:"SUB_DOMAIN"`
	Domain          string `gorm:"column:domain;type:char(64);not null" mapstructure:"DOMAIN"`
}
