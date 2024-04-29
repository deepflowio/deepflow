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

	"github.com/deepflowio/deepflow/server/agent_config"
)

type ControllerUpdate struct {
	VtapMax int      `json:"VTAP_MAX" binding:"min=0,max=10000"`
	Region  string   `json:"REGION"`
	Azs     []string `json:"AZS"`
	IsAllAz bool     `json:"IS_ALL_AZ"`
	State   int      `json:"STATE"`
	NatIP   string   `json:"NAT_IP"`
}

type ControllerAz struct {
	Az     string `json:"AZ"`
	AzName string `json:"AZ_NAME"`
}

type Controller struct {
	ID                 int            `json:"ID"`
	IP                 string         `json:"IP"`
	Name               string         `json:"NAME"`
	NodeType           int            `json:"NODE_TYPE"`
	State              int            `json:"STATE"`
	PodIP              string         `json:"POD_IP"`
	NatIP              string         `json:"NAT_IP"`
	NatIPEnabled       int            `json:"NAT_IP_ENABLED"`
	CPUNum             int            `json:"CPU_NUM"`
	MemorySize         int64          `json:"MEMORY_SIZE"`
	Arch               string         `json:"ARCH"`
	ArchType           int            `json:"ARCH_TYPE"`
	Os                 string         `json:"OS"`
	OsType             int            `json:"OS_TYPE"`
	KernelVersion      string         `json:"KERNEL_VERSION"`
	VtapCount          int            `json:"VTAP_COUNT"`
	CurVtapCount       int            `json:"CUR_VTAP_COUNT"`
	VTapMax            int            `json:"VTAP_MAX"`
	RegionDomainPrefix string         `json:"REGION_DOMAIN_PREFIX"`
	SyncedAt           time.Time      `json:"SYNCED_AT"`
	Region             string         `json:"REGION"`
	RegionName         string         `json:"REGION_NAME"`
	IsAllAz            bool           `json:"IS_ALL_AZ"`
	Azs                []ControllerAz `json:"AZS"`
	Lcuuid             string         `json:"LCUUID"`
}

type AnalyzerUpdate struct {
	VtapMax int      `json:"VTAP_MAX" binding:"min=0,max=10000"`
	Region  string   `json:"REGION"`
	Azs     []string `json:"AZS"`
	IsAllAz bool     `json:"IS_ALL_AZ"`
	State   int      `json:"STATE"`
	NatIP   string   `json:"NAT_IP"`
	Agg     int      `json:"AGG"`
}

type AnalyzerAz struct {
	Az     string `json:"AZ"`
	AzName string `json:"AZ_NAME"`
}

type Analyzer struct {
	ID                int          `json:"ID"`
	IP                string       `json:"IP"`
	Name              string       `json:"NAME"`
	State             int          `json:"STATE"`
	PodIP             string       `json:"POD_IP"`
	NatIP             string       `json:"NAT_IP"`
	NatIPEnabled      int          `json:"NAT_IP_ENABLED"`
	Agg               int          `json:"AGG"`
	CPUNum            int          `json:"CPU_NUM"`
	MemorySize        int64        `json:"MEMORY_SIZE"`
	Arch              string       `json:"ARCH"`
	ArchType          int          `json:"ARCH_TYPE"`
	Os                string       `json:"OS"`
	OsType            int          `json:"OS_TYPE"`
	KernelVersion     string       `json:"KERNEL_VERSION"`
	VtapCount         int          `json:"VTAP_COUNT"`
	CurVtapCount      int          `json:"CUR_VTAP_COUNT"`
	VTapMax           int          `json:"VTAP_MAX"`
	PcapDataMountPath string       `json:"PCAP_DATA_MOUNT_PATH"`
	SyncedAt          time.Time    `json:"SYNCED_AT"`
	Region            string       `json:"REGION"`
	RegionName        string       `json:"REGION_NAME"`
	IsAllAz           bool         `json:"IS_ALL_AZ"`
	Azs               []AnalyzerAz `json:"AZS"`
	Lcuuid            string       `json:"LCUUID"`
}

type VtapCreate struct {
	Name            string `json:"NAME" binding:"required"`
	Type            int    `json:"TYPE" binding:"required"`
	CtrlIP          string `json:"CTRL_IP" binding:"required"`
	CtrlMac         string `json:"CTRL_MAC"`
	AZ              string `json:"AZ" binding:"required"`
	Region          string `json:"REGION" binding:"required"`
	VtapGroupLcuuid string `json:"VTAP_GROUP_LCUUID" binding:"required"`
	TeamID          int    `json:"TEAM_ID" binding:"required"`
}

type VtapUpdate struct {
	Lcuuid           string `json:"LCUUID"`
	Enable           int    `json:"ENABLE"`
	State            int    `json:"STATE"`
	VtapGroupLcuuid  string `json:"VTAP_GROUP_LCUUID"`
	LicenseType      int    `json:"LICENSE_TYPE"`
	LicenseFunctions []int  `json:"LICENSE_FUNCTIONS"`
}

type Vtap struct {
	ID                 int     `json:"ID"`
	Name               string  `json:"NAME"`
	State              int     `json:"STATE"`
	Enable             int     `json:"ENABLE"`
	LaunchServer       string  `json:"LAUNCH_SERVER"`
	LaunchServerID     int     `json:"LAUNCH_SERVER_ID"`
	Type               int     `json:"TYPE"`
	CtrlIP             string  `json:"CTRL_IP"`
	CtrlMac            string  `json:"CTRL_MAC"`
	ControllerIP       string  `json:"CONTROLLER_IP"`
	AnalyzerIP         string  `json:"ANALYZER_IP"`
	CurControllerIP    string  `json:"CUR_CONTROLLER_IP"`
	CurAnalyzerIP      string  `json:"CUR_ANALYZER_IP"`
	SyncedControllerAt string  `json:"SYNCED_CONTROLLER_AT"`
	SyncedAnalyzerAt   string  `json:"SYNCED_ANALYZER_AT"`
	BootTime           int     `json:"BOOT_TIME"`
	Revision           string  `json:"REVISION"`
	UpgradeRevision    string  `json:"UPGRADE_REVISION"`
	CompleteRevision   string  `json:"COMPLETE_REVISION"`
	Exceptions         []int64 `json:"EXCEPTIONS"`
	VtapGroupLcuuid    string  `json:"VTAP_GROUP_LCUUID"`
	VtapGroupName      string  `json:"VTAP_GROUP_NAME"`
	AZ                 string  `json:"AZ"`
	AZName             string  `json:"AZ_NAME"`
	Region             string  `json:"REGION"`
	RegionName         string  `json:"REGION_NAME"`
	CPUNum             int     `json:"CPU_NUM"`
	MemorySize         int64   `json:"MEMORY_SIZE"`
	Arch               string  `json:"ARCH"`
	ArchType           int     `json:"ARCH_TYPE"`
	Os                 string  `json:"OS"`
	OsType             int     `json:"OS_TYPE"`
	KernelVersion      string  `json:"KERNEL_VERSION"`
	ProcessName        string  `json:"PROCESS_NAME"`
	LicenseType        int     `json:"LICENSE_TYPE"`
	LicenseFunctions   []int   `json:"LICENSE_FUNCTIONS"`
	ExpectedRevision   string  `json:"EXPECTED_REVISION"`
	UpgradePackage     string  `json:"UPGRADE_PACKAGE"`
	TapMode            int     `json:"TAP_MODE"`
	Lcuuid             string  `json:"LCUUID"`
	TeamID             int     `json:"TEAM_ID"`
	// TODO: format_state
	// TODO: format_type
	// TODO: format_exceptions
}

type VtapUpdateTapMode struct {
	VTapLcuuids []string `json:"VTAP_LCUUIDS"`
	TapMode     int      `json:"TAP_MODE"`
}

type VtapRepo struct {
	Name      string `json:"NAME"`
	Arch      string `json:"ARCH" binding:"required"`
	OS        string `json:"OS"`
	Branch    string `json:"BRANCH"`
	RevCount  string `json:"REV_COUNT"`
	CommitID  string `json:"COMMIT_ID"`
	Image     []byte `json:"IMAGE,omitempty" binding:"required"`
	UpdatedAt string `json:"UPDATED_AT"`
}

type HostVTapRebalanceResult struct {
	IP                string  `json:"IP"`
	AZ                string  `json:"AZ"`
	State             int     `json:"STATE"`
	BeforeVTapNum     int     `json:"BEFORE_VTAP_NUM"`
	AfterVTapNum      int     `json:"AFTER_VTAP_NUM"`
	SwitchVTapNum     int     `json:"SWITCH_VTAP_NUM"`
	BeforeVTapWeights float64 `json:"BEFORE_VTAP_WEIGHTS"`
	AfterVTapWeights  float64 `json:"AFTER_VTAP_WEIGHTS"`

	// debug data
	NewVTapToTraffic  map[string]int64 `json:"-"`
	DelVTapToTraffic  map[string]int64 `json:"-"`
	BeforeVTapTraffic int64            `json:"-"`
	AfterVTapTraffic  int64            `json:"-"`
}

type AZVTapRebalanceResult struct {
	TotalSwitchVTapNum int                        `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []*HostVTapRebalanceResult `json:"DETAILS"`
}

type VTapRebalanceResult struct {
	TotalSwitchVTapNum int                        `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []*HostVTapRebalanceResult `json:"DETAILS"`
}

type VtapGroup struct {
	ID                 int      `json:"ID"`
	Name               string   `json:"NAME"`
	UpdatedAt          string   `json:"UPDATED_AT"`
	ShortUUID          string   `json:"SHORT_UUID"`
	Lcuuid             string   `json:"LCUUID"`
	TeamID             int      `json:"TEAM_ID"`
	VtapLcuuids        []string `json:"VTAP_LCUUIDS"`
	DisableVtapLcuuids []string `json:"DISABLE_VTAP_LCUUIDS"`
	PendingVtapLcuuids []string `json:"PENDING_VTAP_LCUUIDS"`
}

type VtapGroupCreate struct {
	Name        string   `json:"NAME"`
	State       int      `json:"STATE"`
	Enable      int      `json:"ENABLE"`
	VtapLcuuids []string `json:"VTAP_LCUUIDS"`
	GroupID     string   `json:"GROUP_ID"`
	TeamID      int      `json:"TEAM_ID"`
}

type VtapGroupUpdate struct {
	Name        string   `json:"NAME"`
	State       int      `json:"STATE"`
	Enable      int      `json:"ENABLE"`
	VtapLcuuids []string `json:"VTAP_LCUUIDS"`
}

type DataSource struct {
	ID                        int    `json:"ID"`
	Name                      string `json:"NAME"`
	DisplayName               string `json:"DISPLAY_NAME"`
	DataTableCollection       string `json:"DATA_TABLE_COLLECTION"`
	State                     int    `json:"STATE"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID"`
	BaseDataSourceDisplayName string `json:"BASE_DATA_SOURCE_NAME"`
	Interval                  int    `json:"INTERVAL"`
	RetentionTime             int    `json:"RETENTION_TIME"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR"`
	IsDefault                 bool   `json:"IS_DEFAULT"`
	UpdatedAt                 string `json:"UPDATED_AT"`
	Lcuuid                    string `json:"LCUUID"`
}

type DataSourceCreate struct {
	DisplayName               string `json:"DISPLAY_NAME" binding:"required,min=1,max=10"`
	DataTableCollection       string `json:"DATA_TABLE_COLLECTION" binding:"required,oneof=flow_metrics.network* flow_metrics.application*"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID" binding:"required"`
	Interval                  int    `json:"INTERVAL" binding:"required"`
	RetentionTime             int    `json:"RETENTION_TIME" binding:"required,min=1"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Sum Max Min"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Avg Max Min"`
}

type DataSourceUpdate struct {
	RetentionTime int    `json:"RETENTION_TIME" binding:"required,min=1"`
	DisplayName   string `json:"DISPLAY_NAME"`
}

type LicenseConsumption struct {
	LicenseType     int `json:"LICENSE_TYPE"`
	LicenseFunction int `json:"LICENSE_FUNCTION"`

	Total     int `json:"TOTAL"`
	Avaliable int `json:"AVALIABLE"`
	Used      int `json:"CONSUMPTION"`
}

type VTapLicenseConsumption struct {
	ID               int    `json:"ID"`
	Name             string `json:"NAME"`
	Type             int    `json:"TYPE"`
	LicenseType      int    `json:"LICENSE_TYPE"`
	LicenseFunctions []int  `json:"LICENSE_FUNCTIONS"`
	Lcuuid           string `json:"LCUUID"`

	LicenseUsedCount int `json:"LICENSE_CONSUME"`
}

type Domain struct {
	ID             string                 `json:"ID"`
	Name           string                 `json:"NAME"`
	DisplayName    string                 `json:"DISPLAY_NAME"`
	ClusterID      string                 `json:"CLUSTER_ID"`
	Type           int                    `json:"TYPE"`
	Enabled        int                    `json:"ENABLED"`
	State          int                    `json:"STATE"`
	ErrorMsg       string                 `json:"ERROR_MSG"`
	ControllerIP   string                 `json:"CONTROLLER_IP"`
	ControllerName string                 `json:"CONTROLLER_NAME"`
	VTapName       string                 `json:"VTAP_NAME"`
	VTapCtrlIP     string                 `json:"VTAP_CTRL_IP"`
	VTapCtrlMAC    string                 `json:"VTAP_CTRL_MAC"`
	IconID         int                    `json:"ICON_ID"`
	TeamID         int                    `json:"TEAM_ID"`
	K8sEnabled     int                    `json:"K8S_ENABLED"`
	Config         map[string]interface{} `json:"CONFIG"`
	AZCount        int                    `json:"AZ_COUNT"`
	RegionCount    int                    `json:"REGION_COUNT"`
	PodClusters    []string               `json:"POD_CLUSTERS"`
	CreatedAt      string                 `json:"CREATED_AT"`
	SyncedAt       string                 `json:"SYNCED_AT"`
	Lcuuid         string                 `json:"LCUUID"`
}

type DomainCreate struct {
	Name                string                 `json:"NAME" binding:"required"`
	Type                int                    `json:"TYPE" binding:"required"`
	TeamID              int                    `json:"TEAM_ID"`
	KubernetesClusterID string                 `json:"KUBERNETES_CLUSTER_ID"`
	IconID              int                    `json:"ICON_ID"`       // TODO: 修改为required
	ControllerIP        string                 `json:"CONTROLLER_IP"` // TODO: 修改为required
	Config              map[string]interface{} `json:"CONFIG"`
}

type DomainUpdate struct {
	Name         string                 `json:"NAME"`
	Enabled      int                    `json:"ENABLED"`
	IconID       int                    `json:"ICON_ID"`
	TeamID       int                    `json:"TEAM_ID"`
	ControllerIP string                 `json:"CONTROLLER_IP"`
	Config       map[string]interface{} `json:"CONFIG"`
}

type SubDomain struct {
	ID           int                    `json:"ID"`
	Name         string                 `json:"NAME"`
	DisplayName  string                 `json:"DISPLAY_NAME"`
	ClusterID    string                 `json:"CLUSTER_ID"`
	State        int                    `json:"STATE"`
	ErrorMsg     string                 `json:"ERROR_MSG"`
	VPCName      string                 `json:"EPC_NAME"`
	Domain       string                 `json:"DOMAIN"`
	Config       map[string]interface{} `json:"CONFIG"`
	CreateMethod int                    `json:"CREATE_METHOD"`
	CreatedAt    string                 `json:"CREATED_AT"`
	SyncedAt     string                 `json:"SYNCED_AT"`
	Lcuuid       string                 `json:"LCUUID"`
	DomainName   string                 `json:"DOMAIN_NAME"`
}

type SubDomainCreate struct {
	Name   string                 `json:"NAME" binding:"required"`
	Config map[string]interface{} `json:"CONFIG" binding:"required"`
	Domain string                 `json:"DOMAIN" binding:"required"`
}

type SubDomainUpdate struct {
	Config map[string]interface{} `json:"CONFIG"`
}

type AdditionalResourceAZ struct {
	Name       string `json:"name" yaml:"name" binding:"required"`
	UUID       string `json:"uuid" yaml:"uuid" binding:"required"`
	DomainUUID string `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
}

type AdditionalResourceVPC struct {
	Name       string `json:"name" yaml:"name" binding:"required"`
	UUID       string `json:"uuid" yaml:"uuid" binding:"required"`
	DomainUUID string `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
}

type AdditionalResourceSubnet struct {
	Name       string   `json:"name" yaml:"name" binding:"required"`
	UUID       string   `json:"uuid,omitempty" yaml:"uuid" binding:"required"`
	IsVIP      bool     `json:"is_vip" yaml:"is_vip"`
	Type       int      `json:"type" yaml:"type"`
	VPCUUID    string   `json:"vpc_uuid" yaml:"vpc_uuid" binding:"required"`
	AZUUID     string   `json:"az_uuid,omitempty" yaml:"az_uuid"`
	DomainUUID string   `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	CIDRs      []string `json:"cidrs" yaml:"cidrs"`
}

type AdditionalResourceHost struct {
	Name        string                         `json:"name" yaml:"name" binding:"required"`
	UUID        string                         `json:"uuid" yaml:"uuid" binding:"required"`
	IP          string                         `json:"ip" yaml:"ip" binding:"required"`
	Type        int                            `json:"type" yaml:"type"`
	AZUUID      string                         `json:"az_uuid" yaml:"az_uuid" binding:"required"`
	DomainUUID  string                         `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	VInterfaces []AdditionalResourceVInterface `json:"vinterfaces" yaml:"vinterfaces"`
}

type AdditionalResourceChost struct {
	Name        string                         `json:"name" yaml:"name" binding:"required"`
	UUID        string                         `json:"uuid" yaml:"uuid" binding:"required"`
	HostIP      string                         `json:"host_ip" yaml:"host_ip"`
	Type        int                            `json:"type" yaml:"type"`
	VPCUUID     string                         `json:"vpc_uuid" yaml:"vpc_uuid" binding:"required"`
	AZUUID      string                         `json:"az_uuid" yaml:"az_uuid" binding:"required"`
	DomainUUID  string                         `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	VInterfaces []AdditionalResourceVInterface `json:"vinterfaces" yaml:"vinterfaces"`
}

type AdditionalResourceVInterface struct {
	SubnetUUID string   `json:"subnet_uuid" yaml:"subnet_uuid"`
	Name       string   `json:"name,omitempty" yaml:"name"`
	Mac        string   `json:"mac" yaml:"mac" binding:"required"`
	IPs        []string `json:"ips" yaml:"ips"`
}

type AdditionalResourceCloudTag struct {
	ResourceType  string                  `json:"resource_type" yaml:"resource_type" binding:"required"`
	ResourceName  string                  `json:"resource_name" yaml:"resource_name" binding:"required"`
	DomainUUID    string                  `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	SubDomainUUID string                  `json:"subdomain_uuid,omitempty" yaml:"subdomain_uuid"`
	Tags          []AdditionalResourceTag `json:"tags" yaml:"tags" binding:"required"`
}

type AdditionalResourceTag struct {
	Key   string `json:"key" yaml:"key" binding:"required"`
	Value string `json:"value" yaml:"value" binding:"required"`
}

type AdditionalResourceLB struct {
	Name        string                         `json:"name" yaml:"name" binding:"required"`
	Model       int                            `json:"model" yaml:"model" binding:"required,oneof=1 2"`
	VPCUUID     string                         `json:"vpc_uuid" yaml:"vpc_uuid" binding:"required"`
	RegionUUID  string                         `json:"region_uuid" yaml:"region_uuid" binding:"required"`
	DomainUUID  string                         `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	VInterfaces []AdditionalResourceVInterface `json:"vinterfaces" yaml:"vinterfaces" binding:"omitempty,dive"`
	LBListeners []AdditionalResourceLBListener `json:"lb_listeners" yaml:"lb_listeners" binding:"omitempty,dive"`
}

type AdditionalResourceLBListener struct {
	Name            string                             `json:"name" yaml:"name"`
	Protocol        string                             `json:"protocol" yaml:"protocol" binding:"required,oneof=TCP UDP"`
	IP              string                             `json:"ip" yaml:"ip" binding:"required"`
	Port            int                                `json:"port" yaml:"port" binding:"required"`
	LBTargetServers []AdditionalResourceLBTargetServer `json:"lb_target_servers" yaml:"lb_target_servers" binding:"omitempty,dive"`
}

type AdditionalResourceLBTargetServer struct {
	IP   string `json:"ip" yaml:"ip" binding:"required"`
	Port int    `json:"port" yaml:"port" binding:"required"`
}

type AdditionalResourcePeerConnection struct {
	Name             string `json:"name" yaml:"name" binding:"required"`
	UUID             string `json:"uuid" yaml:"uuid" binding:"required"`
	DomainUUID       string `json:"domain_uuid" yaml:"domain_uuid" binding:"required"`
	LocalVPCUUID     string `json:"local_vpc_uuid" yaml:"local_vpc_uuid" binding:"required"`
	LocalRegionUUID  string `json:"local_region_uuid" yaml:"local_region_uuid" binding:"required"`
	RemoteVPCUUID    string `json:"remote_vpc_uuid" yaml:"remote_vpc_uuid" binding:"required"`
	RemoteRegionUUID string `json:"remote_region_uuid" yaml:"remote_region_uuid" binding:"required"`
}

type AdditionalResource struct {
	AZs             []AdditionalResourceAZ             `json:"azs" yaml:"azs,omitempty" binding:"omitempty,dive"`
	VPCs            []AdditionalResourceVPC            `json:"vpcs" yaml:"vpcs,omitempty" binding:"omitempty,dive"`
	Subnets         []AdditionalResourceSubnet         `json:"subnets" yaml:"subnets,omitempty" binding:"omitempty,dive"`
	Hosts           []AdditionalResourceHost           `json:"hosts" yaml:"hosts,omitempty" binding:"omitempty,dive"`
	CHosts          []AdditionalResourceChost          `json:"chosts" yaml:"chosts,omitempty" binding:"omitempty,dive"`
	CloudTags       []AdditionalResourceCloudTag       `json:"cloud_tags" yaml:"cloud_tags,omitempty" binding:"omitempty,dive"`
	LB              []AdditionalResourceLB             `json:"lbs" yaml:"lbs,omitempty" binding:"omitempty,dive"`
	PeerConnections []AdditionalResourcePeerConnection `json:"peer_connections" yaml:"peer_connections,omitempty" binding:"omitempty,dive"`
}

type DetailedConfig struct {
	RealConfig    *agent_config.AgentGroupConfigResponse `json:"REAL_CONFIG"`
	DefaultConfig *agent_config.AgentGroupConfigResponse `json:"DEFAULT_CONFIG"`
}

type VTapInterface struct {
	ID                 int    `json:"ID"`
	Name               string `json:"NAME"`
	MAC                string `json:"MAC"`
	TapName            string `json:"TAP_NAME"`
	TapMAC             string `json:"TAP_MAC"`
	VTapID             int    `json:"VTAP_ID"`
	VTapType           int    `json:"VTAP_TYPE"`
	VTapName           string `json:"VTAP_NAME"`
	VTapLaunchServer   string `json:"VTAP_LAUNCH_SERVER"`
	VTapLaunchServerID int    `json:"VTAP_LAUNCH_SERVER_ID"`
	DeviceName         string `json:"DEVICE_NAME"`
	DeviceType         int    `json:"DEVICE_TYPE"`
	DeviceID           int    `json:"DEVICE_ID"`
	DeviceHostID       int    `json:"DEVICE_HOST_ID"`
	DeviceHostName     string `json:"DEVICE_HOST_NAME"`
	HostIP             string `json:"HOST_IP"`
	NodeIP             string `json:"NODE_IP"`
	LastSeen           string `json:"LAST_SEEN"`
}

type GenesisHost struct {
	VtapID   uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid   string `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Hostname string `gorm:"column:hostname;type:varchar(256);default:null" json:"HOSTNAME"`
	IP       string `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	NodeIP   string `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisHost) TableName() string {
	return "genesis_host"
}

type GenesisIP struct {
	Masklen          uint32    `gorm:"column:masklen;type:int;default:null;default:0" json:"MASKLEN"`
	VtapID           uint32    `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	IP               string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Lcuuid           string    `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	VinterfaceLcuuid string    `gorm:"column:vinterface_lcuuid;type:char(64);default:null" json:"VINTERFACE_LCUUID"`
	NodeIP           string    `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
	LastSeen         time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisIP) TableName() string {
	return "genesis_ip"
}

type GenesisVIP struct {
	VtapID uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	IP     string `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Lcuuid string `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	NodeIP string `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisVIP) TableName() string {
	return "genesis_vip"
}

type GenesisLldp struct {
	VtapID                uint32    `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid                string    `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	HostIP                string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	HostInterface         string    `gorm:"column:host_interface;type:char(64);default:null" json:"HOST_INTERFACE"`
	SystemName            string    `gorm:"column:system_name;type:varchar(512);default:null" json:"SYSTEM_NAME"`
	ManagementAddress     string    `gorm:"column:management_address;type:varchar(512);default:null" json:"MANAGEMENT_ADDRESS"`
	VinterfaceLcuuid      string    `gorm:"column:vinterface_lcuuid;type:varchar(512);default:null" json:"VINTERFACE_LCUUID"`
	VinterfaceDescription string    `gorm:"column:vinterface_description;type:varchar(512);default:null" json:"VINTERFACE_DESCRIPTION"`
	NodeIP                string    `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
	LastSeen              time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisLldp) TableName() string {
	return "genesis_lldp"
}

type GenesisNetwork struct {
	SegmentationID uint32 `gorm:"column:segmentation_id;type:int;default:null" json:"SEGMENTATION_ID"`
	NetType        uint32 `gorm:"column:net_type;type:int;default:null" json:"NET_TYPE"`
	VtapID         uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	External       bool   `gorm:"column:external;type:tinyint(1);default:null" json:"EXTERNAL"`
	Name           string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Lcuuid         string `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	VPCLcuuid      string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	NodeIP         string `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisNetwork) TableName() string {
	return "genesis_network"
}

type GenesisPort struct {
	Type          uint32 `gorm:"column:type;type:int;default:null" json:"TYPE"`
	DeviceType    uint32 `gorm:"column:device_type;type:int;default:null" json:"DEVICETYPE"`
	VtapID        uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid        string `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Mac           string `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	DeviceLcuuid  string `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	NetworkLcuuid string `gorm:"column:network_lcuuid;type:char(64);default:null" json:"NETWORK_LCUUID"`
	VPCLcuuid     string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	NodeIP        string `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisPort) TableName() string {
	return "genesis_port"
}

type GenesisVinterface struct {
	NetnsID             uint32    `gorm:"column:netns_id;type:int unsigned;default:0" json:"NETNS_ID"`
	VtapID              uint32    `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid              string    `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Name                string    `gorm:"column:name;type:char(64);default:null" json:"NAME"`
	IPs                 string    `gorm:"column:ips;type:text;default:null" json:"IPS"`
	Mac                 string    `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	TapName             string    `gorm:"column:tap_name;type:char(64);default:null" json:"TAP_NAME"`
	TapMac              string    `gorm:"column:tap_mac;type:char(32);default:null" json:"TAP_MAC"`
	DeviceLcuuid        string    `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	DeviceName          string    `gorm:"column:device_name;type:varchar(512);default:null" json:"DEVICE_NAME"`
	DeviceType          string    `gorm:"column:device_type;type:char(64);default:null" json:"DEVICE_TYPE"`
	IFType              string    `gorm:"column:if_type;type:char(64);default:null" json:"IF_TYPE"`
	HostIP              string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	KubernetesClusterID string    `gorm:"column:kubernetes_cluster_id;type:char(64);default:null" json:"KUBERNETES_CLUSTER_ID"`
	NodeIP              string    `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
	LastSeen            time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisVinterface) TableName() string {
	return "genesis_vinterface"
}

type GenesisVM struct {
	State        uint32    `gorm:"column:state;type:int;default:null" json:"STATE"`
	VtapID       uint32    `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid       string    `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Name         string    `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Label        string    `gorm:"column:label;type:char(64);default:null" json:"LABEL"`
	VPCLcuuid    string    `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	LaunchServer string    `gorm:"column:launch_server;type:char(64);default:null" json:"LAUNCH_SERVER"`
	NodeIP       string    `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
}

func (GenesisVM) TableName() string {
	return "genesis_vm"
}

type GenesisVpc struct {
	VtapID uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	Lcuuid string `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Name   string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	NodeIP string `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisVpc) TableName() string {
	return "genesis_vpc"
}

type GenesisProcess struct {
	NetnsID     uint32    `gorm:"column:netns_id;type:int unsigned;default:0" json:"NETNS_ID"`
	VtapID      uint32    `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	PID         uint64    `gorm:"column:pid;type:int;default:null" json:"PID"`
	Lcuuid      string    `gorm:"primaryKey;column:lcuuid;type:char(64)" json:"LCUUID"`
	Name        string    `gorm:"column:name;type:text;default:null" json:"NAME"`
	ProcessName string    `gorm:"column:process_name;type:text;default:null" json:"PROCESS_NAME"`
	CMDLine     string    `gorm:"column:cmd_line;type:text;default:null" json:"CMD_LINE"`
	ContainerID string    `gorm:"column:container_id;type:char(64);default:''" json:"CONTAINER_ID"`
	User        string    `gorm:"column:user;type:varchar(256);default:null" json:"USER"`
	OSAPPTags   string    `gorm:"column:os_app_tags;type:text;default:null" json:"OS_APP_TAGS"`
	NodeIP      string    `gorm:"primaryKey;column:node_ip;type:char(48)" json:"NODE_IP"`
	StartTime   time.Time `gorm:"column:start_time;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"START_TIME"`
}

func (GenesisProcess) TableName() string {
	return "genesis_process"
}

type GenesisStorage struct {
	VtapID uint32 `gorm:"primaryKey;column:vtap_id;type:int" json:"VTAP_ID"`
	NodeIP string `gorm:"column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisStorage) TableName() string {
	return "genesis_storage"
}

type Process struct {
	ResourceType int    `json:"RESOURCE_TYPE"` // 1: vm 14: pod node
	ResourceName string `json:"RESOURCE_NAME"`
	Name         string `json:"NAME"`
	VTapName     string `json:"VTAP_NAME"`
	GPID         int    `json:"GPID"`
	GPName       string `json:"GP_NAME"` // equal to process.process_name
	PID          uint64 `json:"PID"`
	ProcessName  string `json:"PROCESS_NAME"`
	CommandLine  string `json:"CMD_LINE"`
	UserName     string `json:"USER_NAME"`
	OSAPPTags    string `json:"OS_APP_TAGS"`
	ResourceID   int    `json:"RESOURCE_ID"`
	StartTime    string `json:"START_TIME"`
	UpdateAt     string `json:"UPDATE_AT"`
	DeletedAt    string `json:"DELETED_AT"`
}

type CSV struct {
	Headers []CSVHeader `json:"CSV_HEADERS"`
}

type CSVHeader struct {
	DisplayName string `json:"DISPLAY_NAME"`
	FieldName   string `json:"FIELD_NAME"`
}

type Plugin struct {
	Name      string `json:"NAME" binding:"required"`
	Type      int    `json:"TYPE" binding:"required"`
	Image     []byte `json:"IMAGE,omitempty" binding:"required"`
	UpdatedAt string `json:"UPDATED_AT"`
}

type MailServerCreate struct {
	Status       int    `json:"STATUS"`
	Host         string `json:"HOST" binding:"required"`
	Port         int    `json:"PORT" binding:"required"`
	User         string `json:"USER" binding:"required"`
	Password     string `json:"PASSWORD" binding:"required"`
	NtlmEnabled  int    `json:"NTLM_ENABLED"`
	NtlmName     string `json:"NTLM_NAME"`
	NtlmPassword string `json:"NTLM_PASSWORD"`
	Security     string `json:"SECURITY" binding:"required"`
}

type MailServerUpdate struct {
	Status       int    `json:"STATUS"`
	Host         string `json:"HOST"`
	Port         int    `json:"PORT"`
	User         string `json:"USER"`
	Password     string `json:"PASSWORD"`
	NtlmEnabled  int    `json:"NTLM_ENABLED"`
	NtlmName     string `json:"NTLM_NAME"`
	NtlmPassword string `json:"NTLM_PASSWORD"`
	Security     string `json:"SECURITY"`
}

type MailServer struct {
	ID           int    `json:"ID"`
	Status       int    `json:"STATUS"`
	Host         string `json:"HOST"`
	Port         int    `json:"PORT"`
	User         string `json:"USER"`
	Password     string `json:"PASSWORD"`
	Security     string `json:"SECURITY"`
	NtlmEnabled  int    `json:"NTLM_ENABLED"`
	NtlmName     string `json:"NTLM_NAME"`
	NtlmPassword string `json:"NTLM_PASSWORD"`
	Lcuuid       string `json:"LCUUID"`
}
