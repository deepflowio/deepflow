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

package model

import (
	"time"
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
	DataTableCollection       string `json:"DATA_TABLE_COLLECTION" binding:"required,oneof=flow_metrics.vtap_flow* flow_metrics.vtap_app*"`
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
	KubernetesClusterID string                 `json:"KUBERNETES_CLUSTER_ID"`
	IconID              int                    `json:"ICON_ID"`       // TODO: 修改为required
	ControllerIP        string                 `json:"CONTROLLER_IP"` // TODO: 修改为required
	Config              map[string]interface{} `json:"CONFIG"`
}

type DomainUpdate struct {
	Name         string                 `json:"NAME"`
	Enabled      int                    `json:"ENABLED"`
	IconID       int                    `json:"ICON_ID"`
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
	SubDomainUUID string                  `json:"subdomain_uuid" yaml:"subdomain_uuid"`
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

type AdditionalResource struct {
	AZs       []AdditionalResourceAZ       `json:"azs" yaml:"azs" binding:"omitempty,dive"`
	VPCs      []AdditionalResourceVPC      `json:"vpcs" yaml:"vpcs" binding:"omitempty,dive"`
	Subnets   []AdditionalResourceSubnet   `json:"subnets" yaml:"subnets" binding:"omitempty,dive"`
	Hosts     []AdditionalResourceHost     `json:"hosts" yaml:"hosts" binding:"omitempty,dive"`
	CHosts    []AdditionalResourceChost    `json:"chosts" yaml:"chosts" binding:"omitempty,dive"`
	CloudTags []AdditionalResourceCloudTag `json:"cloud_tags" yaml:"cloud_tags" binding:"omitempty,dive"`
	LB        []AdditionalResourceLB       `json:"lbs" yaml:"lbs" binding:"omitempty,dive"`
}

type VTapGroupConfiguration struct {
	VTapGroupID                   *string       `json:"VTAP_GROUP_ID" yaml:"vtap_group_id,omitempty"`
	VTapGroupLcuuid               *string       `json:"VTAP_GROUP_LCUUID" yaml:"vtap_group_lcuuid,omitempty"`
	MaxCollectPps                 *int          `json:"MAX_COLLECT_PPS" yaml:"max_collect_pps,omitempty"`
	MaxNpbBps                     *int64        `json:"MAX_NPB_BPS" yaml:"max_npb_bps,omitempty"` // unit: bps
	MaxCPUs                       *int          `json:"MAX_CPUS" yaml:"max_cpus,omitempty"`
	MaxMemory                     *int          `json:"MAX_MEMORY" yaml:"max_memory,omitempty"` // unit: M
	SyncInterval                  *int          `json:"SYNC_INTERVAL" yaml:"sync_interval,omitempty"`
	StatsInterval                 *int          `json:"STATS_INTERVAL" yaml:"stats_interval,omitempty"`
	RsyslogEnabled                *int          `json:"RSYSLOG_ENABLED" yaml:"rsyslog_enabled,omitempty"`   // 0: disabled 1:enabled
	MaxTxBandwidth                *int64        `json:"MAX_TX_BANDWIDTH" yaml:"max_tx_bandwidth,omitempty"` // unit: bps
	BandwidthProbeInterval        *int          `json:"BANDWIDTH_PROBE_INTERVAL" yaml:"bandwidth_probe_interval,omitempty"`
	TapInterfaceRegex             *string       `json:"TAP_INTERFACE_REGEX" yaml:"tap_interface_regex,omitempty"`
	MaxEscapeSeconds              *int          `json:"MAX_ESCAPE_SECONDS" yaml:"max_escape_seconds,omitempty"`
	Mtu                           *int          `json:"MTU" yaml:"mtu,omitempty"`
	OutputVlan                    *int          `json:"OUTPUT_VLAN" yaml:"output_vlan,omitempty"`
	CollectorSocketType           *string       `json:"COLLECTOR_SOCKET_TYPE" yaml:"collector_socket_type,omitempty"`
	CompressorSocketType          *string       `json:"COMPRESSOR_SOCKET_TYPE" yaml:"compressor_socket_type,omitempty"`
	NpbSocketType                 *string       `json:"NPB_SOCKET_TYPE" yaml:"npb_socket_type,omitempty"`
	NpbVlanMode                   *int          `json:"NPB_VLAN_MODE" yaml:"npb_vlan_mode,omitempty"`
	CollectorEnabled              *int          `json:"COLLECTOR_ENABLED" yaml:"collector_enabled,omitempty"`             // 0: disabled 1:enabled
	VTapFlow1sEnabled             *int          `json:"VTAP_FLOW_1S_ENABLED" yaml:"vtap_flow_1s_enabled,omitempty"`       // 0: disabled 1:enabled
	L4LogTapTypes                 []int         `json:"L4_LOG_TAP_TYPES" yaml:"l4_log_tap_types,omitempty"`               // tap type info, separate by ","
	L4LogIgnoreTapSides           []int         `json:"L4_LOG_IGNORE_TAP_SIDES" yaml:"l4_log_ignore_tap_sides,omitempty"` // separate by ","
	L7LogIgnoreTapSides           []int         `json:"L7_LOG_IGNORE_TAP_SIDES" yaml:"l7_log_ignore_tap_sides,omitempty"` // separate by ","
	NpbDedupEnabled               *int          `json:"NPB_DEDUP_ENABLED" yaml:"npb_dedup_enabled,omitempty"`             // 0: disabled 1:enabled
	PlatformEnabled               *int          `json:"PLATFORM_ENABLED" yaml:"platform_enabled,omitempty"`               // 0: disabled 1:enabled
	IfMacSource                   *int          `json:"IF_MAC_SOURCE" yaml:"if_mac_source,omitempty"`                     // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     *string       `json:"VM_XML_PATH" yaml:"vm_xml_path,omitempty"`
	ExtraNetnsRegex               *string       `json:"EXTRA_NETNS_REGEX" yaml:"extra_netns_regex,omitempty"`
	NatIPEnabled                  *int          `json:"NAT_IP_ENABLED" yaml:"nat_ip_enabled,omitempty"` // 0: disabled 1:enabled
	CapturePacketSize             *int          `json:"CAPTURE_PACKET_SIZE" yaml:"capture_packet_size,omitempty"`
	InactiveServerPortEnabled     *int          `json:"INACTIVE_SERVER_PORT_ENABLED" yaml:"inactive_server_port_enabled,omitempty"` // 0: disabled 1:enabled
	InactiveIPEnabled             *int          `json:"INACTIVE_IP_ENABLED" yaml:"inactive_ip_enabled,omitempty"`                   // 0: disabled 1:enabled
	LogThreshold                  *int          `json:"LOG_THRESHOLD" yaml:"log_threshold,omitempty"`
	LogLevel                      *string       `json:"LOG_LEVEL" yaml:"log_level,omitempty"`
	LogRetention                  *int          `json:"LOG_RETENTION" yaml:"log_retention,omitempty"`
	HTTPLogProxyClient            *string       `json:"HTTP_LOG_PROXY_CLIENT" yaml:"http_log_proxy_client,omitempty"`
	HTTPLogTraceID                *string       `json:"HTTP_LOG_TRACE_ID" yaml:"http_log_trace_id,omitempty"`
	L7LogPacketSize               *int          `json:"L7_LOG_PACKET_SIZE" yaml:"l7_log_packet_size,omitempty"`
	L4LogCollectNpsThreshold      *int          `json:"L4_LOG_COLLECT_NPS_THRESHOLD" yaml:"l4_log_collect_nps_threshold,omitempty"`
	L7LogCollectNpsThreshold      *int          `json:"L7_LOG_COLLECT_NPS_THRESHOLD" yaml:"l7_log_collect_nps_threshold,omitempty"`
	L7MetricsEnabled              *int          `json:"L7_METRICS_ENABLED" yaml:"l7_metrics_enabled,omitempty"`         // 0: disabled 1:enabled
	L7LogStoreTapTypes            []int         `json:"L7_LOG_STORE_TAP_TYPES" yaml:"l7_log_store_tap_types,omitempty"` // l7 log store tap types, separate by ","
	CaptureSocketType             *int          `json:"CAPTURE_SOCKET_TYPE" yaml:"capture_socket_type,omitempty"`
	CaptureBpf                    *string       `json:"CAPTURE_BPF" yaml:"capture_bpf,omitempty"`
	TapMode                       *int          `json:"TAP_MODE" yaml:"tap_mode,omitempty"`
	ThreadThreshold               *int          `json:"THREAD_THRESHOLD" yaml:"thread_threshold,omitempty"`
	ProcessThreshold              *int          `json:"PROCESS_THRESHOLD" yaml:"process_threshold,omitempty"`
	Lcuuid                        *string       `json:"LCUUID" yaml:"-"`
	NtpEnabled                    *int          `json:"NTP_ENABLED" yaml:"ntp_enabled,omitempty"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled          *int          `json:"L4_PERFORMANCE_ENABLED" yaml:"l4_performance_enabled,omitempty"`   // 0: disabled 1:enabled
	PodClusterInternalIP          *int          `json:"POD_CLUSTER_INTERNAL_IP" yaml:"pod_cluster_internal_ip,omitempty"` // 0:  1:
	Domains                       []string      `json:"DOMAINS" yaml:"domains,omitempty"`                                 // domains info, separate by ","
	DecapType                     []int         `json:"DECAP_TYPE" yaml:"decap_type,omitempty"`                           // separate by ","
	HTTPLogSpanID                 *string       `json:"HTTP_LOG_SPAN_ID" yaml:"http_log_span_id,omitempty"`
	SysFreeMemoryLimit            *int          `json:"SYS_FREE_MEMORY_LIMIT" yaml:"sys_free_memory_limit,omitempty"` // unit: %
	LogFileSize                   *int          `json:"LOG_FILE_SIZE" yaml:"log_file_size,omitempty"`                 // unit: MB
	HTTPLogXRequestID             *string       `json:"HTTP_LOG_X_REQUEST_ID" yaml:"http_log_x_request_id,omitempty"`
	ExternalAgentHTTPProxyEnabled *int          `json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED" yaml:"external_agent_http_proxy_enabled,omitempty"`
	ExternalAgentHTTPProxyPort    *int          `json:"EXTERNAL_AGENT_HTTP_PROXY_PORT" yaml:"external_agent_http_proxy_port,omitempty"`
	PrometheusHttpAPIAddresses    []string      `json:"PROMETHEUS_HTTP_API_ADDRESSES" yaml:"prometheus_http_api_addresses,omitempty"` // ip:port
	AnalyzerPort                  *int          `json:"ANALYZER_PORT" yaml:"analyzer_port,omitempty"`
	ProxyControllerPort           *int          `json:"PROXY_CONTROLLER_PORT" yaml:"proxy_controller_port,omitempty"`
	ProxyControllerIP             *string       `json:"PROXY_CONTROLLER_IP" yaml:"proxy_controller_ip,omitempty"`
	AnalyzerIP                    *string       `json:"ANALYZER_IP" yaml:"analyzer_ip,omitempty"`
	YamlConfig                    *StaticConfig `yaml:"static_config,omitempty"`
}

type TypeInfo struct {
	ID   int    `json:"ID"`
	Name string `json:"NAME"`
}

type DomainInfo struct {
	ID   string `json:"ID"`
	Name string `json:"NAME"`
}

type TapSideInfo struct {
	ID   int    `json:"ID"`
	Name string `json:"NAME"`
}

type VTapGroupConfigurationResponse struct {
	MaxCollectPps                 *int           `json:"MAX_COLLECT_PPS"`
	MaxNpbBps                     *int64         `json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                       *int           `json:"MAX_CPUS"`
	MaxMemory                     *int           `json:"MAX_MEMORY"` // unit: M
	SyncInterval                  *int           `json:"SYNC_INTERVAL"`
	StatsInterval                 *int           `json:"STATS_INTERVAL"`
	RsyslogEnabled                *int           `json:"RSYSLOG_ENABLED"`  // 0: disabled 1:enabled
	MaxTxBandwidth                *int64         `json:"MAX_TX_BANDWIDTH"` // unit: bps
	BandwidthProbeInterval        *int           `json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex             *string        `json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds              *int           `json:"MAX_ESCAPE_SECONDS"`
	Mtu                           *int           `json:"MTU"`
	OutputVlan                    *int           `json:"OUTPUT_VLAN"`
	CollectorSocketType           *string        `json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType          *string        `json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                 *string        `json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                   *int           `json:"NPB_VLAN_MODE"`
	CollectorEnabled              *int           `json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled             *int           `json:"VTAP_FLOW_1S_ENABLED"`    // 0: disabled 1:enabled
	L4LogTapTypes                 []*TypeInfo    `json:"L4_LOG_TAP_TYPES"`        // tap type info, separate by ","
	L4LogIgnoreTapSides           []*TapSideInfo `json:"L4_LOG_IGNORE_TAP_SIDES"` // separate by ","
	L7LogIgnoreTapSides           []*TapSideInfo `json:"L7_LOG_IGNORE_TAP_SIDES"` // separate by ","
	NpbDedupEnabled               *int           `json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled               *int           `json:"PLATFORM_ENABLED"`        // 0: disabled 1:enabled
	IfMacSource                   *int           `json:"IF_MAC_SOURCE"`           // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     *string        `json:"VM_XML_PATH"`
	ExtraNetnsRegex               *string        `json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                  *int           `json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize             *int           `json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled     *int           `json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled             *int           `json:"INACTIVE_IP_ENABLED"`          // 0: disabled 1:enabled
	VTapGroupLcuuid               *string        `json:"VTAP_GROUP_LCUUID"`
	VTapGroupID                   *string        `json:"VTAP_GROUP_ID"`
	VTapGroupName                 *string        `json:"VTAP_GROUP_NAME"`
	LogThreshold                  *int           `json:"LOG_THRESHOLD"`
	LogLevel                      *string        `json:"LOG_LEVEL"`
	LogRetention                  *int           `json:"LOG_RETENTION"`
	HTTPLogProxyClient            *string        `json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                *string        `json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize               *int           `json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold      *int           `json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold      *int           `json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled              *int           `json:"L7_METRICS_ENABLED"`     // 0: disabled 1:enabled
	L7LogStoreTapTypes            []*TypeInfo    `json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType             *int           `json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                    *string        `json:"CAPTURE_BPF"`
	TapMode                       *int           `json:"TAP_MODE"`
	ThreadThreshold               *int           `json:"THREAD_THRESHOLD"`
	ProcessThreshold              *int           `json:"PROCESS_THRESHOLD"`
	Lcuuid                        *string        `json:"LCUUID"`
	NtpEnabled                    *int           `json:"NTP_ENABLED"`             // 0: disabled 1:enabled
	L4PerformanceEnabled          *int           `json:"L4_PERFORMANCE_ENABLED"`  // 0: disabled 1:enabled
	PodClusterInternalIP          *int           `json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                       []*DomainInfo  `json:"DOMAINS"`                 // domains info, separate by ","
	DecapType                     []*TypeInfo    `json:"DECAP_TYPE"`              // separate by ","
	HTTPLogSpanID                 *string        `json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit            *int           `json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                   *int           `json:"LOG_FILE_SIZE"`         // unit: MB
	HTTPLogXRequestID             *string        `json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled *int           `json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort    *int           `json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	PrometheusHttpAPIAddresses    *string        `json:"PROMETHEUS_HTTP_API_ADDRESSES"` // separate by ","
	AnalyzerPort                  *int           `json:"ANALYZER_PORT"`
	ProxyControllerPort           *int           `json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP             *string        `json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                    *string        `json:"ANALYZER_IP"`
}

type DetailedConfig struct {
	RealConfig    *VTapGroupConfigurationResponse `json:"REAL_CONFIG"`
	DefaultConfig *VTapGroupConfigurationResponse `json:"DEFAULT_CONFIG"`
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

// TODO: 因为genesis的功能还未完全迁移完，且数据库字段不相同，所以这里启用了一组新的表来支持，等待完成迁移后将表趋于统一并删除无用表。
// 这里为了保持一致性和泛型方便添加一个参考的lcuuid，可以使用common.GetUUID(Hostname)来获得
type GenesisHost struct {
	ID       int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID   uint32 `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid   string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Hostname string `gorm:"column:hostname;type:varchar(256);default:null" json:"HOSTNAME"`
	IP       string `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	NodeIP   string `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
}

func (GenesisHost) TableName() string {
	return "go_genesis_host"
}

type GenesisIP struct {
	ID               int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Masklen          uint32    `gorm:"column:masklen;type:int;default:null;default:0" json:"MASKLEN"`
	VtapID           uint32    `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	IP               string    `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Lcuuid           string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	VinterfaceLcuuid string    `gorm:"column:vinterface_lcuuid;type:char(64);default:null" json:"VINTERFACE_LCUUID"`
	NodeIP           string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	LastSeen         time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisIP) TableName() string {
	return "go_genesis_ip"
}

type GenesisVIP struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID uint32 `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	IP     string `gorm:"column:ip;type:char(64);default:null" json:"IP"`
	Lcuuid string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	NodeIP string `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
}

func (GenesisVIP) TableName() string {
	return "go_genesis_vip"
}

type GenesisLldp struct {
	ID                    int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID                uint32    `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid                string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	HostIP                string    `gorm:"column:host_ip;type:char(48);default:null" json:"HOST_IP"`
	HostInterface         string    `gorm:"column:host_interface;type:char(64);default:null" json:"HOST_INTERFACE"`
	SystemName            string    `gorm:"column:system_name;type:varchar(512);default:null" json:"SYSTEM_NAME"`
	ManagementAddress     string    `gorm:"column:management_address;type:varchar(512);default:null" json:"MANAGEMENT_ADDRESS"`
	VinterfaceLcuuid      string    `gorm:"column:vinterface_lcuuid;type:varchar(512);default:null" json:"VINTERFACE_LCUUID"`
	VinterfaceDescription string    `gorm:"column:vinterface_description;type:varchar(512);default:null" json:"VINTERFACE_DESCRIPTION"`
	NodeIP                string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	LastSeen              time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisLldp) TableName() string {
	return "go_genesis_lldp"
}

type GenesisNetwork struct {
	ID             int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	SegmentationID uint32 `gorm:"column:segmentation_id;type:int;default:null" json:"SEGMENTATION_ID"`
	NetType        uint32 `gorm:"column:net_type;type:int;default:null" json:"NET_TYPE"`
	VtapID         uint32 `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	External       bool   `gorm:"column:external;type:tinyint(1);default:null" json:"EXTERNAL"`
	Name           string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Lcuuid         string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	VPCLcuuid      string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	NodeIP         string `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
}

func (GenesisNetwork) TableName() string {
	return "go_genesis_network"
}

type GenesisPort struct {
	ID            int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	Type          uint32 `gorm:"column:type;type:int;default:null" json:"TYPE"`
	DeviceType    uint32 `gorm:"column:device_type;type:int;default:null" json:"DEVICETYPE"`
	VtapID        uint32 `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid        string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Mac           string `gorm:"column:mac;type:char(32);default:null" json:"MAC"`
	DeviceLcuuid  string `gorm:"column:device_lcuuid;type:char(64);default:null" json:"DEVICE_LCUUID"`
	NetworkLcuuid string `gorm:"column:network_lcuuid;type:char(64);default:null" json:"NETWORK_LCUUID"`
	VPCLcuuid     string `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	NodeIP        string `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
}

func (GenesisPort) TableName() string {
	return "go_genesis_port"
}

type GenesisVinterface struct {
	ID                  int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	NetnsID             uint32    `gorm:"column:netns_id;type:int unsigned;default:0" json:"NETNS_ID"`
	VtapID              uint32    `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid              string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
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
	NodeIP              string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	LastSeen            time.Time `gorm:"column:last_seen;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"LAST_SEEN"`
}

func (GenesisVinterface) TableName() string {
	return "go_genesis_vinterface"
}

type GenesisVM struct {
	ID           int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	State        uint32    `gorm:"column:state;type:int;default:null" json:"STATE"`
	VtapID       uint32    `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid       string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name         string    `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	Label        string    `gorm:"column:label;type:char(64);default:null" json:"LABEL"`
	VPCLcuuid    string    `gorm:"column:vpc_lcuuid;type:char(64);default:null" json:"VPC_LCUUID"`
	LaunchServer string    `gorm:"column:launch_server;type:char(64);default:null" json:"LAUNCH_SERVER"`
	NodeIP       string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	CreatedAt    time.Time `gorm:"column:created_at;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"CREATED_AT"`
}

func (GenesisVM) TableName() string {
	return "go_genesis_vm"
}

type GenesisVpc struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID uint32 `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	Lcuuid string `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name   string `gorm:"column:name;type:varchar(256);default:null" json:"NAME"`
	NodeIP string `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
}

func (GenesisVpc) TableName() string {
	return "go_genesis_vpc"
}

type GenesisProcess struct {
	ID          int       `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	NetnsID     uint32    `gorm:"column:netns_id;type:int unsigned;default:0" json:"NETNS_ID"`
	VtapID      uint32    `gorm:"column:vtap_id;type:int;default:null" json:"VTAP_ID"`
	PID         uint64    `gorm:"column:pid;type:int;default:null" json:"PID"`
	Lcuuid      string    `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	Name        string    `gorm:"column:name;type:text;default:null" json:"NAME"`
	ProcessName string    `gorm:"column:process_name;type:text;default:null" json:"PROCESS_NAME"`
	CMDLine     string    `gorm:"column:cmd_line;type:text;default:null" json:"CMD_LINE"`
	ContainerID string    `gorm:"column:container_id;type:char(64);default:''" json:"CONTAINER_ID"`
	User        string    `gorm:"column:user;type:varchar(256);default:null" json:"USER"`
	OSAPPTags   string    `gorm:"column:os_app_tags;type:text;default:null" json:"OS_APP_TAGS"`
	NodeIP      string    `gorm:"column:node_ip;type:char(48);default:null" json:"NODE_IP"`
	StartTime   time.Time `gorm:"column:start_time;type:datetime;not null;default:CURRENT_TIMESTAMP" json:"START_TIME"`
}

func (GenesisProcess) TableName() string {
	return "go_genesis_process"
}

type GenesisStorage struct {
	ID     int    `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	VtapID uint32 `gorm:"column:vtap_id;type:int" json:"VTAP_ID"`
	NodeIP string `gorm:"column:node_ip;type:char(48)" json:"NODE_IP"`
}

func (GenesisStorage) TableName() string {
	return "go_genesis_storage"
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
