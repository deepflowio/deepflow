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
	VTapMax           int          `json:"VTAP_MAX"`
	PcapDataMountPath string       `json:"PCAP_DATA_MOUNT_PATH"`
	SyncedAt          time.Time    `json:"SYNCED_AT"`
	Region            string       `json:"REGION"`
	RegionName        string       `json:"REGION_NAME"`
	IsAllAz           bool         `json:"IS_ALL_AZ"`
	Azs               []AnalyzerAz `json:"AZS"`
	Lcuuid            string       `json:"LCUUID"`
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
	Az                 string  `json:"AZ"`
	AzName             string  `json:"AZ_NAME"`
	Region             string  `json:"REGION"`
	RegionName         string  `json:"REGION_NAME"`
	CPUNum             int     `json:"CPU_NUM"`
	MemorySize         int64   `json:"MEMORY_SIZE"`
	Arch               string  `json:"ARCH"`
	ArchType           int     `json:"ARCH_TYPE"`
	Os                 string  `json:"OS"`
	OsType             int     `json:"OS_TYPE"`
	KernelVersion      string  `json:"KERNEL_VERSION"`
	LicenseType        int     `json:"LICENSE_TYPE"`
	LicenseFunctions   []int   `json:"LICENSE_FUNCTIONS"`
	Lcuuid             string  `json:"LCUUID"`
	// TODO: format_state
	// TODO: format_type
	// TODO: format_exceptions
}

type HostVTapRebalanceResult struct {
	IP            string `json:"IP"`
	AZ            string `json:"AZ"`
	State         int    `json:"STATE"`
	BeforeVTapNum int    `json:"BEFORE_VTAP_NUM"`
	AfterVTapNum  int    `json:"AFTER_VTAP_NUM"`
	SwitchVTapNum int    `json:"SWITCH_VTAP_NUM"`
}

type AZVTapRebalanceResult struct {
	TotalSwitchVTapNum int                       `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []HostVTapRebalanceResult `json:"DETAILS"`
}

type VTapRebalanceResult struct {
	TotalSwitchVTapNum int                     `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []AZVTapRebalanceResult `json:"DETAILS"`
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
	TsdbType                  string `json:"TSDB_TYPE"`
	State                     int    `json:"STATE"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID`
	BaseDataSourceName        string `json:"BASE_DATA_SOURCE_NAME`
	Interval                  int    `json:"INTERVAL"`
	RetentionTime             int    `json:"RETENTION_TIME"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR"`
	IsDefault                 bool   `json:"IS_DEFAULT"`
	UpdatedAt                 string `json:"UPDATED_AT"`
	Lcuuid                    string `json:"LCUUID"`
}

type DataSourceCreate struct {
	Name                      string `json:"NAME" binding:"required,min=1,max=10"`
	TsdbType                  string `json:"TSDB_TYPE" binding:"required,oneof=flow app"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID" binding:"required"`
	Interval                  int    `json:"INTERVAL" binding:"required"`
	RetentionTime             int    `json:"RETENTION_TIME" binding:"required,min=1"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Sum Max Min"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Avg Max Min"`
}

type DataSourceUpdate struct {
	RetentionTime int `json:"RETENTION_TIME" binding:"required,min=1"`
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
	ID             int                    `json:"ID"`
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
	Name         string                 `json:"NAME" binding:"required"`
	Type         int                    `json:"TYPE" binding:"required"`
	IconID       int                    `json:"ICON_ID"`       // TODO: 修改为required
	ControllerIP string                 `json:"CONTROLLER_IP"` // TODO: 修改为required
	Config       map[string]interface{} `json:"CONFIG" binding:"required"`
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
}

type SubDomainCreate struct {
	Name   string                 `json:"NAME" binding:"required"`
	Config map[string]interface{} `json:"CONFIG" binding:"required"`
	Domain string                 `json:"DOMAIN" binding:"required"`
}

type SubDomainUpdate struct {
	Config map[string]interface{} `json:"CONFIG"`
}

type VTapGroupConfiguration struct {
	MaxCollectPps                 *int     `json:"MAX_COLLECT_PPS" yaml:"max_collect_pps,omitempty"`
	MaxNpbBps                     *int64   `json:"MAX_NPB_BPS" yaml:"max_npb_bps,omitempty"` // unit: bps
	MaxCPUs                       *int     `json:"MAX_CPUS" yaml:"max_cpus,omitempty"`
	MaxMemory                     *int     `json:"MAX_MEMORY" yaml:"max_memory,omitempty"` // unit: M
	SyncInterval                  *int     `json:"SYNC_INTERVAL" yaml:"sync_interval,omitempty"`
	StatsInterval                 *int     `json:"STATS_INTERVAL" yaml:"stats_interval,omitempty"`
	RsyslogEnabled                *int     `json:"RSYSLOG_ENABLED" yaml:"rsyslog_enabled,omitempty"`   // 0: disabled 1:enabled
	MaxTxBandwidth                *int64   `json:"MAX_TX_BANDWIDTH" yaml:"max_tx_bandwidth,omitempty"` // unit: bps
	BandwidthProbeInterval        *int     `json:"BANDWIDTH_PROBE_INTERVAL" yaml:"bandwidth_probe_interval,omitempty"`
	TapInterfaceRegex             *string  `json:"TAP_INTERFACE_REGEX" yaml:"tap_interface_regex,omitempty"`
	MaxEscapeSeconds              *int     `json:"MAX_ESCAPE_SECONDS" yaml:"max_escape_seconds,omitempty"`
	Mtu                           *int     `json:"MTU" yaml:"mtu,omitempty"`
	OutputVlan                    *int     `json:"OUTPUT_VLAN" yaml:"output_vlan,omitempty"`
	CollectorSocketType           *string  `json:"COLLECTOR_SOCKET_TYPE" yaml:"collector_socket_type,omitempty"`
	CompressorSocketType          *string  `json:"COMPRESSOR_SOCKET_TYPE" yaml:"compressor_socket_type,omitempty"`
	NpbSocketType                 *string  `json:"NPB_SOCKET_TYPE" yaml:"npb_socket_type,omitempty"`
	NpbVlanMode                   *int     `json:"NPB_VLAN_MODE" yaml:"npb_vlan_mode,omitempty"`
	CollectorEnabled              *int     `json:"COLLECTOR_ENABLED" yaml:"collector_enabled,omitempty"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled             *int     `json:"VTAP_FLOW_1S_ENABLED" yaml:"vtap_flow_1s_enabled,omitempty"` // 0: disabled 1:enabled
	L4LogTapTypes                 []int    `json:"L4_LOG_TAP_TYPES" yaml:"l4_log_tap_types,omitempty"`         // tap type info, separate by ","
	NpbDedupEnabled               *int     `json:"NPB_DEDUP_ENABLED" yaml:"npb_dedup_enabled,omitempty"`       // 0: disabled 1:enabled
	PlatformEnabled               *int     `json:"PLATFORM_ENABLED" yaml:"platform_enabled,omitempty"`         // 0: disabled 1:enabled
	IfMacSource                   *int     `json:"IF_MAC_SOURCE" yaml:"if_mac_source,omitempty"`               // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     *string  `json:"VM_XML_PATH" yaml:"vm_xml_path,omitempty"`
	NatIPEnabled                  *int     `json:"NAT_IP_ENABLED" yaml:"nat_ip_enabled,omitempty"` // 0: disabled 1:enabled
	CapturePacketSize             *int     `json:"CAPTURE_PACKET_SIZE" yaml:"capture_packet_size,omitempty"`
	InactiveServerPortEnabled     *int     `json:"INACTIVE_SERVER_PORT_ENABLED" yaml:"inactive_server_port_enabled,omitempty"` // 0: disabled 1:enabled
	VTapGroupLcuuid               *string  `json:"VTAP_GROUP_LCUUID" yaml:"-"`
	LogThreshold                  *int     `json:"LOG_THRESHOLD" yaml:"log_threshold,omitempty"`
	LogLevel                      *string  `json:"LOG_LEVEL" yaml:"log_level,omitempty"`
	LogRetention                  *int     `json:"LOG_RETENTION" yaml:"log_retention,omitempty"`
	HTTPLogProxyClient            *string  `json:"HTTP_LOG_PROXY_CLIENT" yaml:"http_log_proxy_client,omitempty"`
	HTTPLogTraceID                *string  `json:"HTTP_LOG_TRACE_ID" yaml:"http_log_trace_id,omitempty"`
	L7LogPacketSize               *int     `json:"L7_LOG_PACKET_SIZE" yaml:"l7_log_packet_size,omitempty"`
	L4LogCollectNpsThreshold      *int     `json:"L4_LOG_COLLECT_NPS_THRESHOLD" yaml:"l4_log_collect_nps_threshold,omitempty"`
	L7LogCollectNpsThreshold      *int     `json:"L7_LOG_COLLECT_NPS_THRESHOLD" yaml:"l7_log_collect_nps_threshold,omitempty"`
	L7MetricsEnabled              *int     `json:"L7_METRICS_ENABLED" yaml:"l7_metrics_enabled,omitempty"`         // 0: disabled 1:enabled
	L7LogStoreTapTypes            []int    `json:"L7_LOG_STORE_TAP_TYPES" yaml:"l7_log_store_tap_types,omitempty"` // l7 log store tap types, separate by ","
	CaptureSocketType             *int     `json:"CAPTURE_SOCKET_TYPE" yaml:"capture_socket_type,omitempty"`
	CaptureBpf                    *string  `json:"CAPTURE_BPF" yaml:"capture_bpf,omitempty"`
	ThreadThreshold               *int     `json:"THREAD_THRESHOLD" yaml:"thread_threshold,omitempty"`
	ProcessThreshold              *int     `json:"PROCESS_THRESHOLD" yaml:"process_threshold,omitempty"`
	Lcuuid                        *string  `json:"LCUUID" yaml:"-"`
	NtpEnabled                    *int     `json:"NTP_ENABLED" yaml:"ntp_enabled,omitempty"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled          *int     `json:"L4_PERFORMANCE_ENABLED" yaml:"l4_performance_enabled,omitempty"`   // 0: disabled 1:enabled
	PodClusterInternalIP          *int     `json:"POD_CLUSTER_INTERNAL_IP" yaml:"pod_cluster_internal_ip,omitempty"` // 0:  1:
	Domains                       []string `json:"DOMAINS" yaml:"domains,omitempty"`                                 // domains info, separate by ","
	DecapType                     []int    `json:"DECAP_TYPE" yaml:"decap_type,omitempty"`                           // separate by ","
	HTTPLogSpanID                 *string  `json:"HTTP_LOG_SPAN_ID" yaml:"http_log_span_id,omitempty"`
	SysFreeMemoryLimit            *int     `json:"SYS_FREE_MEMORY_LIMIT" yaml:"sys_free_memory_limit,omitempty"` // unit: %
	LogFileSize                   *int     `json:"LOG_FILE_SIZE" yaml:"log_file_size,omitempty"`                 // unit: MB
	HTTPLogXRequestID             *string  `json:"HTTP_LOG_X_REQUEST_ID" yaml:"http_log_x_request_id,omitempty"`
	ExternalAgentHTTPProxyEnabled *int     `json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED" yaml:"external_agent_http_proxy_enabled,omitempty"`
	ExternalAgentHTTPProxyPort    *int     `json:"EXTERNAL_AGENT_HTTP_PROXY_PORT" yaml:"external_agent_http_proxy_port,omitempty"`
	YamlConfig                    *string  `yaml:"advanced_config"`
}

type TypeInfo struct {
	ID   int    `json:"ID"`
	Name string `json:"NAME"`
}

type DomainInfo struct {
	ID   string `json:"ID"`
	Name string `json:"NAME"`
}

type VTapGroupConfigurationResponse struct {
	MaxCollectPps                 *int          `json:"MAX_COLLECT_PPS"`
	MaxNpbBps                     *int64        `json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                       *int          `json:"MAX_CPUS"`
	MaxMemory                     *int          `json:"MAX_MEMORY"` // unit: M
	SyncInterval                  *int          `json:"SYNC_INTERVAL"`
	StatsInterval                 *int          `json:"STATS_INTERVAL"`
	RsyslogEnabled                *int          `json:"RSYSLOG_ENABLED"`  // 0: disabled 1:enabled
	MaxTxBandwidth                *int64        `json:"MAX_TX_BANDWIDTH"` // unit: bps
	BandwidthProbeInterval        *int          `json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex             *string       `json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds              *int          `json:"MAX_ESCAPE_SECONDS"`
	Mtu                           *int          `json:"MTU"`
	OutputVlan                    *int          `json:"OUTPUT_VLAN"`
	CollectorSocketType           *string       `json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType          *string       `json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                 *string       `json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                   *int          `json:"NPB_VLAN_MODE"`
	CollectorEnabled              *int          `json:"COLLECTOR_ENABLED"`    // 0: disabled 1:enabled
	VTapFlow1sEnabled             *int          `json:"VTAP_FLOW_1S_ENABLED"` // 0: disabled 1:enabled
	L4LogTapTypes                 []*TypeInfo   `json:"L4_LOG_TAP_TYPES"`     // tap type info, separate by ","
	NpbDedupEnabled               *int          `json:"NPB_DEDUP_ENABLED"`    // 0: disabled 1:enabled
	PlatformEnabled               *int          `json:"PLATFORM_ENABLED"`     // 0: disabled 1:enabled
	IfMacSource                   *int          `json:"IF_MAC_SOURCE"`        // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                     *string       `json:"VM_XML_PATH"`
	NatIPEnabled                  *int          `json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize             *int          `json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled     *int          `json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	VTapGroupLcuuid               *string       `json:"VTAP_GROUP_LCUUID"`
	LogThreshold                  *int          `json:"LOG_THRESHOLD"`
	LogLevel                      *string       `json:"LOG_LEVEL"`
	LogRetention                  *int          `json:"LOG_RETENTION"`
	HTTPLogProxyClient            *string       `json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                *string       `json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize               *int          `json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold      *int          `json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold      *int          `json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled              *int          `json:"L7_METRICS_ENABLED"`     // 0: disabled 1:enabled
	L7LogStoreTapTypes            []*TypeInfo   `json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType             *int          `json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                    *string       `json:"CAPTURE_BPF"`
	ThreadThreshold               *int          `json:"THREAD_THRESHOLD"`
	ProcessThreshold              *int          `json:"PROCESS_THRESHOLD"`
	Lcuuid                        *string       `json:"LCUUID"`
	NtpEnabled                    *int          `json:"NTP_ENABLED"`             // 0: disabled 1:enabled
	L4PerformanceEnabled          *int          `json:"L4_PERFORMANCE_ENABLED"`  // 0: disabled 1:enabled
	PodClusterInternalIP          *int          `json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                       []*DomainInfo `json:"DOMAINS"`                 // domains info, separate by ","
	DecapType                     []*TypeInfo   `json:"DECAP_TYPE"`              // separate by ","
	HTTPLogSpanID                 *string       `json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit            *int          `json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                   *int          `json:"LOG_FILE_SIZE"`         // unit: MB
	HTTPLogXRequestID             *string       `json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled *int          `json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort    *int          `json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
}

type DetailedConfig struct {
	RealConfig    *VTapGroupConfigurationResponse `json:"REAL_CONFIG"`
	DefaultConfig *VTapGroupConfigurationResponse `json:"DEFAULT_CONFIG"`
}
