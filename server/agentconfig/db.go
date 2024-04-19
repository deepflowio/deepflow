package agentconfig

type AgentGroupConfigModel struct {
	ID                                int      `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MaxCollectPps                     *int     `gorm:"column:max_collect_pps;type:int;default:null" json:"MAX_COLLECT_PPS"`
	MaxNpbBps                         *int64   `gorm:"column:max_npb_bps;type:bigint;default:null" json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                           *int     `gorm:"column:max_cpus;type:int;default:null" json:"MAX_CPUS"`
	MaxMemory                         *int     `gorm:"column:max_memory;type:int;default:null" json:"MAX_MEMORY"` // unit: M
	PlatformSyncInterval              *int     `gorm:"column:platform_sync_interval;type:int;default:null" json:"PLATFORM_SYNC_INTERVAL"`
	SyncInterval                      *int     `gorm:"column:sync_interval;type:int;default:null" json:"SYNC_INTERVAL"`
	StatsInterval                     *int     `gorm:"column:stats_interval;type:int;default:null" json:"STATS_INTERVAL"`
	RsyslogEnabled                    *int     `gorm:"column:rsyslog_enabled;type:tinyint(1);default:null" json:"RSYSLOG_ENABLED"` // 0: disabled 1:enabled
	SystemLoadCircuitBreakerThreshold *float32 `gorm:"column:system_load_circuit_breaker_threshold;type:float(10,2);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_THRESHOLD"`
	SystemLoadCircuitBreakerRecover   *float32 `gorm:"column:system_load_circuit_breaker_recover;type:float(10,2);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_RECOVER"`
	SystemLoadCircuitBreakerMetric    *string  `gorm:"column:system_load_circuit_breaker_metric;type:char(64);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_METRIC"`
	MaxTxBandwidth                    *int64   `gorm:"column:max_tx_bandwidth;type:bigint;default:null" json:"MAX_TX_BANDWIDTH"` // unit: bps
	BandwidthProbeInterval            *int     `gorm:"column:bandwidth_probe_interval;type:int;default:null" json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex                 *string  `gorm:"column:tap_interface_regex;type:text;default:null" json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds                  *int     `gorm:"column:max_escape_seconds;type:int;default:null" json:"MAX_ESCAPE_SECONDS"`
	Mtu                               *int     `gorm:"column:mtu;type:int;default:null" json:"MTU"`
	OutputVlan                        *int     `gorm:"column:output_vlan;type:int;default:null" json:"OUTPUT_VLAN"`
	CollectorSocketType               *string  `gorm:"column:collector_socket_type;type:char(64);default:null" json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType              *string  `gorm:"column:compressor_socket_type;type:char(64);default:null" json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                     *string  `gorm:"column:npb_socket_type;type:char(64);default:null" json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                       *int     `gorm:"column:npb_vlan_mode;type:int;default:null" json:"NPB_VLAN_MODE"`
	CollectorEnabled                  *int     `gorm:"column:collector_enabled;type:tinyint(1);default:null" json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled                 *int     `gorm:"column:vtap_flow_1s_enabled;type:tinyint(1);default:null" json:"VTAP_FLOW_1S_ENABLED"` // 0: disabled 1:enabled
	L4LogTapTypes                     *string  `gorm:"column:l4_log_tap_types;type:text;default:null" json:"L4_LOG_TAP_TYPES"`               // tap type info, separate by ","
	L4LogIgnoreTapSides               *string  `gorm:"column:l4_log_ignore_tap_sides;type:text;default:null" json:"L4_LOG_IGNORE_TAP_SIDES"` // separate by ","
	L7LogIgnoreTapSides               *string  `gorm:"column:l7_log_ignore_tap_sides;type:text;default:null" json:"L7_LOG_IGNORE_TAP_SIDES"` // separate by ","
	NpbDedupEnabled                   *int     `gorm:"column:npb_dedup_enabled;type:tinyint(1);default:null" json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled                   *int     `gorm:"column:platform_enabled;type:tinyint(1);default:null" json:"PLATFORM_ENABLED"`         // 0: disabled 1:enabled
	IfMacSource                       *int     `gorm:"column:if_mac_source;type:int;default:null" json:"IF_MAC_SOURCE"`                      // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                         *string  `gorm:"column:vm_xml_path;type:text;default:null" json:"VM_XML_PATH"`
	ExtraNetnsRegex                   *string  `gorm:"column:extra_netns_regex;type:text;default:null" json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                      *int     `gorm:"column:nat_ip_enabled;type:tinyint(1);default:null" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize                 *int     `gorm:"column:capture_packet_size;type:int;default:null" json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled         *int     `gorm:"column:inactive_server_port_enabled;type:tinyint(1);default:null" json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled                 *int     `gorm:"column:inactive_ip_enabled;type:tinyint(1);default:null" json:"INACTIVE_IP_ENABLED"`                   // 0: disabled 1:enabled
	VTapGroupLcuuid                   *string  `gorm:"column:vtap_group_lcuuid;type:char(64);default:null" json:"VTAP_GROUP_LCUUID"`
	LogThreshold                      *int     `gorm:"column:log_threshold;type:int;default:null" json:"LOG_THRESHOLD"`
	LogLevel                          *string  `gorm:"column:log_level;type:char(64);default:null" json:"LOG_LEVEL"`
	LogRetention                      *int     `gorm:"column:log_retention;type:int;default:null" json:"LOG_RETENTION"`
	HTTPLogProxyClient                *string  `gorm:"column:http_log_proxy_client;type:char(64);default:null" json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                    *string  `gorm:"column:http_log_trace_id;type:text;default:null" json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize                   *int     `gorm:"column:l7_log_packet_size;type:int;default:null" json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold          *int     `gorm:"column:l4_log_collect_nps_threshold;type:int;default:null" json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold          *int     `gorm:"column:l7_log_collect_nps_threshold;type:int;default:null" json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled                  *int     `gorm:"column:l7_metrics_enabled;type:tinyint(1);default:null" json:"L7_METRICS_ENABLED"`   // 0: disabled 1:enabled
	L7LogStoreTapTypes                *string  `gorm:"column:l7_log_store_tap_types;type:text;default:null" json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType                 *int     `gorm:"column:capture_socket_type;type:int;default:null" json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                        *string  `gorm:"column:capture_bpf;type:varchar(512);default:null" json:"CAPTURE_BPF"`
	TapMode                           *int     `gorm:"column:tap_mode;type:int;default:null" json:"TAP_MODE"` // 0: local 1: mirror 2: physical
	ThreadThreshold                   *int     `gorm:"column:thread_threshold;type:int;default:null" json:"THREAD_THRESHOLD"`
	ProcessThreshold                  *int     `gorm:"column:process_threshold;type:int;default:null" json:"PROCESS_THRESHOLD"`
	Lcuuid                            *string  `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	NtpEnabled                        *int     `gorm:"column:ntp_enabled;type:tinyint(1);default:null" json:"NTP_ENABLED"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled              *int     `gorm:"column:l4_performance_enabled;type:tinyint(1);default:null" json:"L4_PERFORMANCE_ENABLED"`   // 0: disabled 1:enabled
	PodClusterInternalIP              *int     `gorm:"column:pod_cluster_internal_ip;type:tinyint(1);default:null" json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                           *string  `gorm:"column:domains;type:text;default:null" json:"DOMAINS"`                                       // domains info, separate by ","
	DecapType                         *string  `gorm:"column:decap_type;type:text;default:null" json:"DECAP_TYPE"`                                 // separate by ","
	HTTPLogSpanID                     *string  `gorm:"column:http_log_span_id;type:text;default:null" json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit                *int     `gorm:"column:sys_free_memory_limit;type:int;default:null" json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                       *int     `gorm:"column:log_file_size;type:int;default:null" json:"LOG_FILE_SIZE"`                 // unit: MB
	HTTPLogXRequestID                 *string  `gorm:"column:http_log_x_request_id;type:char(64);default:null" json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled     *int     `gorm:"column:external_agent_http_proxy_enabled;type:tinyint(1);default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort        *int     `gorm:"column:external_agent_http_proxy_port;type:int;default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	PrometheusHttpAPIAddresses        *string  `gorm:"column:prometheus_http_api_addresses;type:string;default:null" json:"PROMETHEUS_HTTP_API_ADDRESSES"` // ip:port, separate by ","
	AnalyzerPort                      *int     `gorm:"column:analyzer_port;type:int;default:null" json:"ANALYZER_PORT"`
	ProxyControllerPort               *int     `gorm:"column:proxy_controller_port;type:int;default:null" json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP                 *string  `gorm:"column:proxy_controller_ip;type:varchar(512);default:null" json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                        *string  `gorm:"column:analyzer_ip;type:varchar(512);default:null" json:"ANALYZER_IP"`
	WasmPlugins                       *string  `gorm:"column:wasm_plugins;type:text;default:null" json:"WASM_PLUGINS"`
	SoPlugins                         *string  `gorm:"column:so_plugins;type:text;default:null" json:"SO_PLUGINS"`
	YamlConfig                        *string  `gorm:"column:yaml_config;type:text;default:null" json:"YAML_CONFIG"`
}

func (AgentGroupConfigModel) TableName() string {
	return "vtap_group_configuration"
}

// FIXME: This structure is very similar to AgentGroupConfigModel. It should be merged to reduce code redundancy.
// AgentGroupConfigModel [...]
type RAgentGroupConfigModel struct {
	ID                                int     `gorm:"primaryKey;column:id;type:int;not null" json:"ID"`
	MaxCollectPps                     int     `gorm:"column:max_collect_pps;type:int;default:null" json:"MAX_COLLECT_PPS"`
	MaxNpbBps                         int64   `gorm:"column:max_npb_bps;type:bigint;default:null" json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                           int     `gorm:"column:max_cpus;type:int;default:null" json:"MAX_CPUS"`
	MaxMemory                         int     `gorm:"column:max_memory;type:int;default:null" json:"MAX_MEMORY"` // unit: M
	PlatformSyncInterval              int     `gorm:"column:platform_sync_interval;type:int;default:null" json:"PLATFORM_SYNC_INTERVAL"`
	SyncInterval                      int     `gorm:"column:sync_interval;type:int;default:null" json:"SYNC_INTERVAL"`
	StatsInterval                     int     `gorm:"column:stats_interval;type:int;default:null" json:"STATS_INTERVAL"`
	RsyslogEnabled                    int     `gorm:"column:rsyslog_enabled;type:tinyint(1);default:null" json:"RSYSLOG_ENABLED"` // 0: disabled 1:enabled
	SystemLoadCircuitBreakerThreshold float32 `gorm:"column:system_load_circuit_breaker_threshold;type:float(10,2);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_THRESHOLD"`
	SystemLoadCircuitBreakerRecover   float32 `gorm:"column:system_load_circuit_breaker_recover;type:float(10,2);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_RECOVER"`
	SystemLoadCircuitBreakerMetric    string  `gorm:"column:system_load_circuit_breaker_metric;type:char(64);default:null" json:"SYSTEM_LOAD_CIRCUIT_BREAKER_METRIC"`
	MaxTxBandwidth                    int64   `gorm:"column:max_tx_bandwidth;type:bigint;default:null" json:"MAX_TX_BANDWIDTH"` // unit: bps
	BandwidthProbeInterval            int     `gorm:"column:bandwidth_probe_interval;type:int;default:null" json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex                 string  `gorm:"column:tap_interface_regex;type:text;default:null" json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds                  int     `gorm:"column:max_escape_seconds;type:int;default:null" json:"MAX_ESCAPE_SECONDS"`
	Mtu                               int     `gorm:"column:mtu;type:int;default:null" json:"MTU"`
	OutputVlan                        int     `gorm:"column:output_vlan;type:int;default:null" json:"OUTPUT_VLAN"`
	CollectorSocketType               string  `gorm:"column:collector_socket_type;type:char(64);default:null" json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType              string  `gorm:"column:compressor_socket_type;type:char(64);default:null" json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                     string  `gorm:"column:npb_socket_type;type:char(64);default:null" json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                       int     `gorm:"column:npb_vlan_mode;type:int;default:null" json:"NPB_VLAN_MODE"`
	CollectorEnabled                  int     `gorm:"column:collector_enabled;type:tinyint(1);default:null" json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled                 int     `gorm:"column:vtap_flow_1s_enabled;type:tinyint(1);default:null" json:"VTAP_FLOW_1S_ENABLED"` // 0: disabled 1:enabled
	L4LogTapTypes                     string  `gorm:"column:l4_log_tap_types;type:text;default:null" json:"L4_LOG_TAP_TYPES"`               // tap type info, separate by ","
	L4LogIgnoreTapSides               string  `gorm:"column:l4_log_ignore_tap_sides;type:text;default:null" json:"L4_LOG_IGNORE_TAP_SIDES"` // separate by ","
	L7LogIgnoreTapSides               string  `gorm:"column:l7_log_ignore_tap_sides;type:text;default:null" json:"L7_LOG_IGNORE_TAP_SIDES"` // separate by ","
	NpbDedupEnabled                   int     `gorm:"column:npb_dedup_enabled;type:tinyint(1);default:null" json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled                   int     `gorm:"column:platform_enabled;type:tinyint(1);default:null" json:"PLATFORM_ENABLED"`         // 0: disabled 1:enabled
	IfMacSource                       int     `gorm:"column:if_mac_source;type:int;default:null" json:"IF_MAC_SOURCE"`                      // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                         string  `gorm:"column:vm_xml_path;type:text;default:null" json:"VM_XML_PATH"`
	ExtraNetnsRegex                   string  `gorm:"column:extra_netns_regex;type:text;default:null" json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                      int     `gorm:"column:nat_ip_enabled;type:tinyint(1);default:null" json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize                 int     `gorm:"column:capture_packet_size;type:int;default:null" json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled         int     `gorm:"column:inactive_server_port_enabled;type:tinyint(1);default:null" json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled                 int     `gorm:"column:inactive_ip_enabled;type:tinyint(1);default:null" json:"INACTIVE_IP_ENABLED"`                   // 0: disabled 1:enabled
	VTapGroupLcuuid                   string  `gorm:"column:vtap_group_lcuuid;type:char(64);default:null" json:"VTAP_GROUP_LCUUID"`
	LogThreshold                      int     `gorm:"column:log_threshold;type:int;default:null" json:"LOG_THRESHOLD"`
	LogLevel                          string  `gorm:"column:log_level;type:char(64);default:null" json:"LOG_LEVEL"`
	LogRetention                      int     `gorm:"column:log_retention;type:int;default:null" json:"LOG_RETENTION"`
	HTTPLogProxyClient                string  `gorm:"column:http_log_proxy_client;type:char(64);default:null" json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                    string  `gorm:"column:http_log_trace_id;type:text;default:null" json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize                   int     `gorm:"column:l7_log_packet_size;type:int;default:null" json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold          int     `gorm:"column:l4_log_collect_nps_threshold;type:int;default:null" json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold          int     `gorm:"column:l7_log_collect_nps_threshold;type:int;default:null" json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled                  int     `gorm:"column:l7_metrics_enabled;type:tinyint(1);default:null" json:"L7_METRICS_ENABLED"`   // 0: disabled 1:enabled
	L7LogStoreTapTypes                string  `gorm:"column:l7_log_store_tap_types;type:text;default:null" json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType                 int     `gorm:"column:capture_socket_type;type:int;default:null" json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                        string  `gorm:"column:capture_bpf;type:varchar(512);default:null" json:"CAPTURE_BPF"`
	TapMode                           int     `gorm:"column:tap_mode;type:int;default:null" json:"TAP_MODE"` // 0: local 1: mirror 2: physical
	ThreadThreshold                   int     `gorm:"column:thread_threshold;type:int;default:null" json:"THREAD_THRESHOLD"`
	ProcessThreshold                  int     `gorm:"column:process_threshold;type:int;default:null" json:"PROCESS_THRESHOLD"`
	Lcuuid                            string  `gorm:"column:lcuuid;type:char(64);default:null" json:"LCUUID"`
	NtpEnabled                        int     `gorm:"column:ntp_enabled;type:tinyint(1);default:null" json:"NTP_ENABLED"`                         // 0: disabled 1:enabled
	L4PerformanceEnabled              int     `gorm:"column:l4_performance_enabled;type:tinyint(1);default:null" json:"L4_PERFORMANCE_ENABLED"`   // 0: disabled 1:enabled
	PodClusterInternalIP              int     `gorm:"column:pod_cluster_internal_ip;type:tinyint(1);default:null" json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                           string  `gorm:"column:domains;type:text;default:null" json:"DOMAINS"`                                       // domains info, separate by ","
	DecapType                         string  `gorm:"column:decap_type;type:text;default:null" json:"DECAP_TYPE"`                                 // separate by ","
	HTTPLogSpanID                     string  `gorm:"column:http_log_span_id;type:text;default:null" json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit                int     `gorm:"column:sys_free_memory_limit;type:int;default:null" json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                       int     `gorm:"column:log_file_size;type:int;default:null" json:"LOG_FILE_SIZE"`                 // unit: MB
	HTTPLogXRequestID                 string  `gorm:"column:http_log_x_request_id;type:char(64);default:null" json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled     int     `gorm:"column:external_agent_http_proxy_enabled;type:tinyint(1);default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort        int     `gorm:"column:external_agent_http_proxy_port;type:int;default:null" json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	PrometheusHttpAPIAddresses        string  `gorm:"column:prometheus_http_api_addresses;type:string;default:null" json:"PROMETHEUS_HTTP_API_ADDRESSES"` // ip:port, separate by ","
	AnalyzerPort                      int     `gorm:"column:analyzer_port;type:int;default:null" json:"ANALYZER_PORT"`
	ProxyControllerPort               int     `gorm:"column:proxy_controller_port;type:int;default:null" json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP                 string  `gorm:"column:proxy_controller_ip;type:varchar(512);default:null" json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                        string  `gorm:"column:analyzer_ip;type:varchar(512);default:null" json:"ANALYZER_IP"`
	WasmPlugins                       string  `gorm:"column:wasm_plugin;type:text;default:null" json:"WASM_PLUGINS"`
	SoPlugins                         string  `gorm:"column:so_plugin;type:text;default:null" json:"SO_PLUGINS"`
	YamlConfig                        string  `gorm:"column:yaml_config;type:text;default:null" json:"yaml_config"`
}
