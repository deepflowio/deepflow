package agent_config

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

// FIXME: This structure is very similar to VTapGroupConfiguration. It should be merged to reduce code redundancy.
type VTapGroupConfigurationResponse struct {
	MaxCollectPps                     *int           `json:"MAX_COLLECT_PPS"`
	MaxNpbBps                         *int64         `json:"MAX_NPB_BPS"` // unit: bps
	MaxCPUs                           *int           `json:"MAX_CPUS"`
	MaxMemory                         *int           `json:"MAX_MEMORY"` // unit: M
	SyncInterval                      *int           `json:"SYNC_INTERVAL"`
	PlatformSyncInterval              *int           `json:"PLATFORM_SYNC_INTERVAL"`
	StatsInterval                     *int           `json:"STATS_INTERVAL"`
	RsyslogEnabled                    *int           `json:"RSYSLOG_ENABLED"` // 0: disabled 1:enabled
	SystemLoadCircuitBreakerThreshold *float32       `json:"SYSTEM_LOAD_CIRCUIT_BREAKER_THRESHOLD"`
	SystemLoadCircuitBreakerRecover   *float32       `json:"SYSTEM_LOAD_CIRCUIT_BREAKER_RECOVER"`
	SystemLoadCircuitBreakerMetric    *string        `json:"SYSTEM_LOAD_CIRCUIT_BREAKER_METRIC"`
	MaxTxBandwidth                    *int64         `json:"MAX_TX_BANDWIDTH"` // unit: bps
	BandwidthProbeInterval            *int           `json:"BANDWIDTH_PROBE_INTERVAL"`
	TapInterfaceRegex                 *string        `json:"TAP_INTERFACE_REGEX"`
	MaxEscapeSeconds                  *int           `json:"MAX_ESCAPE_SECONDS"`
	Mtu                               *int           `json:"MTU"`
	OutputVlan                        *int           `json:"OUTPUT_VLAN"`
	CollectorSocketType               *string        `json:"COLLECTOR_SOCKET_TYPE"`
	CompressorSocketType              *string        `json:"COMPRESSOR_SOCKET_TYPE"`
	NpbSocketType                     *string        `json:"NPB_SOCKET_TYPE"`
	NpbVlanMode                       *int           `json:"NPB_VLAN_MODE"`
	CollectorEnabled                  *int           `json:"COLLECTOR_ENABLED"`       // 0: disabled 1:enabled
	VTapFlow1sEnabled                 *int           `json:"VTAP_FLOW_1S_ENABLED"`    // 0: disabled 1:enabled
	L4LogTapTypes                     []*TypeInfo    `json:"L4_LOG_TAP_TYPES"`        // tap type info, separate by ","
	L4LogIgnoreTapSides               []*TapSideInfo `json:"L4_LOG_IGNORE_TAP_SIDES"` // separate by ","
	L7LogIgnoreTapSides               []*TapSideInfo `json:"L7_LOG_IGNORE_TAP_SIDES"` // separate by ","
	NpbDedupEnabled                   *int           `json:"NPB_DEDUP_ENABLED"`       // 0: disabled 1:enabled
	PlatformEnabled                   *int           `json:"PLATFORM_ENABLED"`        // 0: disabled 1:enabled
	IfMacSource                       *int           `json:"IF_MAC_SOURCE"`           // 0: 接口MAC 1: 接口名称 2: 虚拟机MAC解析
	VMXMLPath                         *string        `json:"VM_XML_PATH"`
	ExtraNetnsRegex                   *string        `json:"EXTRA_NETNS_REGEX"`
	NatIPEnabled                      *int           `json:"NAT_IP_ENABLED"` // 0: disabled 1:enabled
	CapturePacketSize                 *int           `json:"CAPTURE_PACKET_SIZE"`
	InactiveServerPortEnabled         *int           `json:"INACTIVE_SERVER_PORT_ENABLED"` // 0: disabled 1:enabled
	InactiveIPEnabled                 *int           `json:"INACTIVE_IP_ENABLED"`          // 0: disabled 1:enabled
	VTapGroupLcuuid                   *string        `json:"VTAP_GROUP_LCUUID"`
	VTapGroupID                       *string        `json:"VTAP_GROUP_ID"`
	VTapGroupName                     *string        `json:"VTAP_GROUP_NAME"`
	LogThreshold                      *int           `json:"LOG_THRESHOLD"`
	LogLevel                          *string        `json:"LOG_LEVEL"`
	LogRetention                      *int           `json:"LOG_RETENTION"`
	HTTPLogProxyClient                *string        `json:"HTTP_LOG_PROXY_CLIENT"`
	HTTPLogTraceID                    *string        `json:"HTTP_LOG_TRACE_ID"`
	L7LogPacketSize                   *int           `json:"L7_LOG_PACKET_SIZE"`
	L4LogCollectNpsThreshold          *int           `json:"L4_LOG_COLLECT_NPS_THRESHOLD"`
	L7LogCollectNpsThreshold          *int           `json:"L7_LOG_COLLECT_NPS_THRESHOLD"`
	L7MetricsEnabled                  *int           `json:"L7_METRICS_ENABLED"`     // 0: disabled 1:enabled
	L7LogStoreTapTypes                []*TypeInfo    `json:"L7_LOG_STORE_TAP_TYPES"` // l7 log store tap types, separate by ","
	CaptureSocketType                 *int           `json:"CAPTURE_SOCKET_TYPE"`
	CaptureBpf                        *string        `json:"CAPTURE_BPF"`
	TapMode                           *int           `json:"TAP_MODE"`
	ThreadThreshold                   *int           `json:"THREAD_THRESHOLD"`
	ProcessThreshold                  *int           `json:"PROCESS_THRESHOLD"`
	Lcuuid                            *string        `json:"LCUUID"`
	NtpEnabled                        *int           `json:"NTP_ENABLED"`             // 0: disabled 1:enabled
	L4PerformanceEnabled              *int           `json:"L4_PERFORMANCE_ENABLED"`  // 0: disabled 1:enabled
	PodClusterInternalIP              *int           `json:"POD_CLUSTER_INTERNAL_IP"` // 0:  1:
	Domains                           []*DomainInfo  `json:"DOMAINS"`                 // domains info, separate by ","
	DecapType                         []*TypeInfo    `json:"DECAP_TYPE"`              // separate by ","
	HTTPLogSpanID                     *string        `json:"HTTP_LOG_SPAN_ID"`
	SysFreeMemoryLimit                *int           `json:"SYS_FREE_MEMORY_LIMIT"` // unit: %
	LogFileSize                       *int           `json:"LOG_FILE_SIZE"`         // unit: MB
	HTTPLogXRequestID                 *string        `json:"HTTP_LOG_X_REQUEST_ID"`
	ExternalAgentHTTPProxyEnabled     *int           `json:"EXTERNAL_AGENT_HTTP_PROXY_ENABLED"`
	ExternalAgentHTTPProxyPort        *int           `json:"EXTERNAL_AGENT_HTTP_PROXY_PORT"`
	PrometheusHttpAPIAddresses        *string        `json:"PROMETHEUS_HTTP_API_ADDRESSES"` // separate by ","
	AnalyzerPort                      *int           `json:"ANALYZER_PORT"`
	ProxyControllerPort               *int           `json:"PROXY_CONTROLLER_PORT"`
	ProxyControllerIP                 *string        `json:"PROXY_CONTROLLER_IP"`
	AnalyzerIP                        *string        `json:"ANALYZER_IP"`
	WasmPlugins                       []string       `json:"WASM_PLUGINS"`
	SoPlugins                         []string       `json:"SO_PLUGINS"`
}
