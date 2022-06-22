package model

import "time"

// TODO: 因为genesis的功能还未完全迁移完，且数据库字段不相同，所以这里启用了一组新的表来支持，等待完成迁移后将表趋于统一并删除无用表。

// 这里为了保持一致性和泛型方便添加一个参考的lcuuid，可以使用common.GetUUID(Hostname)来获得
type GenesisHost struct {
	ID       int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid   string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Hostname string `gorm:"column:hostname;type:varchar(256);default:null" json:"HOSTNAME"`
	IP       string `gorm:"column:ip;type:char(64);default:null" json:"IP"`
}

func (GenesisHost) TableName() string {
	return "go_genesis_host"
}

type GenesisIP struct {
	ID               int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Masklen          int       `gorm:"column:masklen;type:int;default:null;default:0" json:"MASKLEN"`
	IP               string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Lcuuid           string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	VinterfaceLcuuid string    `gorm:"column:vinterface_lcuuid;type:char(64);default:null" json:"VINTERFACE_LCUUID"`
	LastSeen         time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisIP) TableName() string {
	return "go_genesis_ip"
}

type GenesisLldp struct {
	ID                    int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid                string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	HostIP                string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	HostInterface         string    `gorm:"column:host_interface;type:char(64);default:null" json:"HOST_INTERFACE"`
	SystemName            string    `gorm:"column:system_name;type:varchar(512);default:null" json:"SYSTEM_NAME"`
	ManagementAddress     string    `gorm:"column:management_address;type:varchar(512);default:null" json:"MANAGEMENT_ADDRESS"`
	VinterfaceLcuuid      string    `gorm:"column:vinterface_lcuuid;type:varchar(512);default:null" json:"VINTERFACE_LCUUID"`
	VinterfaceDescription string    `gorm:"column:vinterface_description;type:varchar(512);default:null" json:"VINTERFACE_DESCRIPTION"`
	LastSeen              time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisLldp) TableName() string {
	return "go_genesis_lldp"
}

type GenesisNetwork struct {
	ID             int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Name           string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Lcuuid         string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	SegmentationID int    `gorm:"column:segmentation_id;type:int;default:null" json:"SEGMENTATION_ID"`
	NetType        int    `gorm:"column:net_type;type:int;default:null" json:"NET_TYPE"`
	External       bool   `gorm:"column:external;type:tinyint(1);default:null" json:"EXTERNAL"`
	VPCLcuuid      string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
}

func (GenesisNetwork) TableName() string {
	return "go_genesis_network"
}

type GenesisPort struct {
	ID            int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid        string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Type          int    `gorm:"column:type;type:int;default:null" json:"TYPE"`
	DeviceType    int    `gorm:"column:device_type;type:int;default:null" json:"DEVICETYPE"`
	Mac           string `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	DeviceLcuuid  string `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	NetworkLcuuid string `gorm:"column:network_lcuuid;type:char(64);default:null" json:"NETWORK_LCUUID"`
	VPCLcuuid     string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
}

func (GenesisPort) TableName() string {
	return "go_genesis_port"
}

type GenesisVinterface struct {
	ID                  int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID              int       `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid              string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name                string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	IPs                 string    `gorm:"column:ips;type:text;default:null" json:"IPS"`
	Mac                 string    `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	TapName             string    `gorm:"column:tap_name;type:char(64);default:null" json:"TAP_NAME"`
	TapMac              string    `gorm:"column:tap_mac;type:char(32);default:null" json:"TAP_MAC"`
	DeviceLcuuid        string    `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	DeviceName          string    `gorm:"column:device_name;type:varchar(512);default:null" json:"DEVICE_NAME"`
	DeviceType          string    `gorm:"column:device_type;type:char(64);default:null" json:"DEVICE_TYPE"`
	HostIP              string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	KubernetesClusterID string    `gorm:"column:kubernetes_cluster_id;type:char(64);default:null" json:"KUBERNETES_CLUSTER_ID"`
	LastSeen            time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisVinterface) TableName() string {
	return "go_genesis_vinterface"
}

type GenesisVM struct {
	ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid       string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name         string    `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Label        string    `gorm:"column:label;type:char(64);default:null" json:"LABEL"`
	VPCLcuuid    string    `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	LaunchServer string    `gorm:"column:launch_server;type:char(64);default:null" json:"LAUNCH_SERVER"`
	State        int       `gorm:"column:state;type:int;default:null" json:"STATE"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
}

func (GenesisVM) TableName() string {
	return "go_genesis_vm"
}

type GenesisVpc struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Lcuuid string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name   string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
}

func (GenesisVpc) TableName() string {
	return "go_genesis_vpc"
}
