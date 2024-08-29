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

package agent_config

type UserConfig struct {
	Global     Global     `yaml:"global,omitempty"`
	Inputs     Inputs     `yaml:"inputs,omitempty"`
	Processors Processors `yaml:"processors,omitempty"`
	Outputs    Outputs    `yaml:"outputs,omitempty"`
	Plugins    Plugins    `yaml:"plugins,omitempty"`
	Dev        Dev        `yaml:"dev,omitempty"`
}

type Global struct {
	Common          GlobalCommon    `yaml:"common,omitempty"`
	Limits          Limits          `yaml:"limits,omitempty"`
	Alerts          Alerts          `yaml:"alerts,omitempty"`
	CircuitBreakers CircuitBreakers `yaml:"Circuit_breakers,omitempty"`
	Tunning         Tunning         `yaml:"tunning,omitempty"`
	Ntp             Ntp             `yaml:"Ntp,omitempty"`
	Communication   Communication   `yaml:"communication,omitempty"`
	SelfMonitoring  SelfMonitoring  `yaml:"self_monitoring,omitempty"`
	StandaloneMode  StandaloneMode  `yaml:"standalone_mode,omitempty"`
}

type GlobalCommon struct {
	Enabled   bool `yaml:"enable,omitempty"`
	AgentType int  `yaml:"agent_type,omitempty"`
}

type Limits struct {
	MaxMillicpus        int    `yaml:"max_millicpus,omitempty"`
	MaxCpus             int    `yaml:"max_cpus,omitempty"`
	MaxMemory           int    `yaml:"max_memory,omitempty"`
	MaxLogBackhaulRate  int    `yaml:"max_log_backhaul_rate,omitempty"`
	MaxLocalLogFileSize int    `yaml:"max_local_log_file_size,omitempty"`
	LocalLogRetention   string `yaml:"local_log_retention,omitempty"`
}

type Alerts struct {
	ThreadThreshold       int  `yaml:"thread_threshold,omitempty"`
	ProcessThreshold      int  `yaml:"process_threshold,omitempty"`
	CheckCoreFileDisabled bool `yaml:"check_core_file_disabled,omitempty"`
}

type CircuitBreakers struct {
	SysFreeMemoryPercentage SysFreeMemoryPercentage `yaml:"sys_free_memory_percentage,omitempty"`
	RelativeSysLoad         RelativeSysLoad         `yaml:"relative_sys_load,omitempty"`
	TxThroughput            TxThroughput            `yaml:"tx_throughput,omitempty"`
}

type SysFreeMemoryPercentage struct {
	Triggerthreshold int `yaml:"trigger_threshold,omitempty"`
}

type RelativeSysLoad struct {
	TriggerThreshold               float32 `yaml:"trigger_threshold,omitempty"`
	RecoveryThreshold              float32 `yaml:"recovery_threshold,omitempty"`
	SystemLoadCircuitBreakerMetric string  `yaml:"system_load_circuit_breaker_metric,omitempty"`
}

type TxThroughput struct {
	TriggerThreshold             int    `yaml:"trigger_threshold,omitempty"`
	ThroughputMonitoringInterval string `yaml:"throughput_monitoring_interval,omitempty"`
}

type Tunning struct {
	CPUAffinity                []int  `yaml:"cpu_affinity,omitempty"`
	ProcessSchedulingPriority  int    `yaml:"process_scheduling_priority,omitempty"`
	IdleMemoryTrimming         bool   `yaml:"idle_memory_trimming,omitempty"`
	ResourceMonitoringInterval string `yaml:"resource_monitoring_interval,omitempty"`
}

type Ntp struct {
	Enabled  bool   `yaml:"enabled,omitempty"`
	MaxDrift string `yaml:"max_drift,omitempty"`
	MinDrift string `yaml:"min_drift,omitempty"`
}

type Communication struct {
	ProactiveRequestInterval string `yaml:"proactive_request_interval,omitempty"`
	MaxEscapeDuration        string `yaml:"max_escape_duration,omitempty"`
	ProxyControllerIP        string `yaml:"proxy_controller_ip,omitempty"`
	ProxyControllerPort      int    `yaml:"proxy_controller_port,omitempty"`
	IngesterIP               string `yaml:"ingester_ip,omitempty"`
	IngesterPort             int    `yaml:"ingester_port,omitempty"`
	GrpcBufferSize           int    `yaml:"grpc_buffer_size,omitempty"`
	RequestViaNatIP          bool   `yaml:"request_via_nat_ip,omitempty"`
}

type SelfMonitoring struct {
	Log      Log     `yaml:"log,omitempty"`
	Profile  Profile `yaml:"profile,omitempty"`
	Debug    Debug   `yaml:"debug,omitempty"`
	Hostname string  `yaml:"hostname,omitempty"`
	Interval string  `yaml:"interval,omitempty"`
}

type Log struct {
	LogLevel           string `yaml:"log_level,omitempty"`
	LogFile            string `yaml:"log_file,omitempty"`
	LogBackhaulEnabled bool   `yaml:"log_backhaul_enabled,omitempty"`
}

type Profile struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

type Debug struct {
	Enabled             bool `yaml:"enabled,omitempty"`
	LocalUDPPort        int  `yaml:"local_udp_port,omitempty"`
	DebugMetricsEnabled bool `yaml:"debug_metrics_enabled,omitempty"`
}

type StandaloneMode struct {
	MaxDataFileSize int    `yaml:"max_data_file_size,omitempty"`
	DataFileDir     string `yaml:"data_file_dir,omitempty"`
}

type Inputs struct {
	Proc        Proc        `yaml:"proc,omitempty"`
	Cbpf        Cbpf        `yaml:"cbpf,omitempty"`
	Ebpf        Ebpf        `yaml:"ebpf,omitempty"`
	Resources   Resources   `yaml:"resources,omitempty"`
	Integration Integration `yaml:"integration,omitempty"`
}

type Proc struct {
	Enabled        bool             `yaml:"enabled,omitempty"`
	ProcDirPath    string           `yaml:"proc_dir_path,omitempty"`
	SyncInterval   string           `yaml:"sync_interval,omitempty"`
	MinLifetime    string           `yaml:"min_lifetime,omitempty"`
	TagExtraction  TagExtraction    `yaml:"tag_extraction,omitempty"`
	ProcessMatcher []ProcessMatcher `yaml:"process_matcher,omitempty"`
	SymbolTable    SymbolTable      `yaml:"symbol_table,omitempty"`
}

type TagExtraction struct {
	ScriptCommand []string `yaml:"script_command,omitempty"`
	ExecUsername  string   `yaml:"exec_username,omitempty"`
}

type ProcessMatcher struct {
	MatchRegex      string   `yaml:"match_regex,omitempty"`
	OnlyInContainer bool     `yaml:"only_in_container,omitempty"`
	EnabledFeatures []string `yaml:"enabled_features,omitempty"`
}

type SymbolTable struct {
	GolangSpecific GolangSpecific `yaml:"golang_specific,omitempty"`
	Java           Java           `yaml:"java,omitempty"`
}

type GolangSpecific struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

type Java struct {
	RefreshDeferDuration string `yaml:"refresh_defer_duration,omitempty"`
	MaxSymbolFileSize    int    `yaml:"max_symbol_file_size,omitempty"`
}

type Cbpf struct {
	Common         Common         `yaml:"common,omitempty"`
	AfPacket       AfPacket       `yaml:"af_packet,omitempty"`
	SpecialNetwork SpecialNetwork `yaml:"special_network,omitempty"`
	Tunning        CbpfTunning    `yaml:"tunning,omitempty"`
	Preprocess     PreProcess     `yaml:"preprocess,omitempty"`
	PhysicalMirror PhysicalMirror `yaml:"physical_mirror,omitempty"`
}

type Common struct {
	CaptureMode int `yaml:"capture_mode,omitempty"`
}

type AfPacket struct {
	InterfaceRegex                 string          `yaml:"interface_regex,omitempty"`
	BondInterfaces                 []BondInterface `yaml:"bond_interfaces,omitempty"`
	ExtraNetnsRegex                string          `yaml:"extra_netns_regex,omitempty"`
	ExtraBpfFilter                 string          `yaml:"extra_bpf_filter,omitempty"`
	SrcInterfaces                  []string        `yaml:"src_interfaces,omitempty"`
	VlanPcpInPhysicalMirrorTraffic int             `yaml:"vlan_pcp_in_physical_mirror_traffic,omitempty"`
	BpfFilterDisabled              bool            `yaml:"bpf_filter_disabled,omitempty"`
	Tunning                        AfPacketTunning `yaml:"tunning,omitempty"`
}

type BondInterface struct {
	SlaveInterfaces []string `yaml:"slave_interfaces,omitempty"`
}

type AfPacketTunning struct {
	SocketVersion     int  `yaml:"socket_version,omitempty"`
	RingBlocksEnabled bool `yaml:"ring_blocks_enabled,omitempty"`
	RingBlocks        int  `yaml:"ring_blocks,omitempty"`
	PacketFanoutCount int  `yaml:"packet_fanout_count,omitempty"`
	PacketFanoutMode  int  `yaml:"packet_fanout_mode,omitempty"`
}

type SpecialNetwork struct {
	Dpdk           Dpdk           `yaml:"dpdk,omitempty"`
	Libpcap        Libpcap        `yaml:"libpcap,omitempty"`
	VhostUser      VhostUser      `yaml:"vhost_user,omitempty"`
	PhysicalSwitch PhysicalSwitch `yaml:"physical_switch,omitempty"`
}

type Dpdk struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

type Libpcap struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

type VhostUser struct {
	VhostSocketPath string `yaml:"vhost_socket_path,omitempty"`
}

type PhysicalSwitch struct {
	SflowPorts   []int `yaml:"sflow_ports,omitempty"`
	NetflowPorts []int `yaml:"netflow_ports,omitempty"`
}

type CbpfTunning struct {
	DispatcherQueueEnabled   bool `yaml:"dispatcher_queue_enabled,omitempty"`
	MaxCapturePacketSize     int  `yaml:"max_capture_packet_size,omitempty"`
	RawPacketBufferBlockSize int  `yaml:"raw_packet_buffer_block_size,omitempty"`
	RawPacketQueueSize       int  `yaml:"raw_packet_queue_size,omitempty"`
	MaxCapturePps            int  `yaml:"max_capture_pps,omitempty"`
}

type PreProcess struct {
	TunnelDecapProtocols         []int    `yaml:"tunnel_decap_protocols,omitempty"`
	TunnelTrimProtocols          []string `yaml:"tunnel_trim_protocols,omitempty"`
	PacketSegmentationReassembly []int    `yaml:"packet_segmentation_reassembly,omitempty"`
}

type PhysicalMirror struct {
	DefaultCaptureNetworkType  int  `yaml:"default_capture_network_type,omitempty"`
	PacketDedupDisabled        bool `yaml:"packet_dedup_disabled,omitempty"`
	PrivateCloudGatewayTraffic bool `yaml:"private_cloud_gateway_traffic,omitempty"`
}

type Ebpf struct {
	Disabled bool        `yaml:"disabled,omitempty"`
	Socket   EbpfSocket  `yaml:"socket,omitempty"`
	File     EbpfFile    `yaml:"file,omitempty"`
	Profile  EbpfProfile `yaml:"profile,omitempty"`
	Tunning  EbpfTunning `yaml:"tunning,omitempty"`
}

type EbpfSocket struct {
	Uprobe     EbpfSocketUprobe     `yaml:"uprobe,omitempty"`
	Kprobe     EbpfSocketKprobe     `yaml:"kprobe,omitempty"`
	Tunning    EbpfSocketTunning    `yaml:"tunning,omitempty"`
	Preprocess EbpfSocketPreprocess `yaml:"preprocess,omitempty"`
}

type EbpfSocketUprobe struct {
	Golang EbpfSocketUprobeGolang `yaml:"golang,omitempty"`
	Tls    EbpfSocketUprobeTls    `yaml:"tls,omitempty"`
}

type EbpfSocketUprobeGolang struct {
	Enabled        bool   `yaml:"enabled,omitempty"`
	TracingTimeout string `yaml:"tracing_timeout,omitempty"`
}

type EbpfSocketUprobeTls struct {
	Enabled bool `yaml:"enabled,omitempty"`
}

type EbpfSocketKprobe struct {
	Blacklist EbpfSocketKprobePorts `yaml:"blacklist,omitempty"`
	Whitelist EbpfSocketKprobePorts `yaml:"whitelist,omitempty"`
}

type EbpfSocketKprobePorts struct {
	Ports string `yaml:"ports,omitempty"`
}

type EbpfSocketTunning struct {
	MaxCaptureRate         int  `yaml:"max_capture_rate,omitempty"`
	SyscallTraceIdDisabled bool `yaml:"syscall_trace_id_disabled,omitempty"`
	MapPreallocDisabled    bool `yaml:"map_prealloc_disabled,omitempty"`
}

type EbpfSocketPreprocess struct {
	OutOfOrderReassemblyCacheSize   int      `yaml:"out_of_order_reassembly_cache_size,omitempty"`
	OutOfOrderReassemblyProtocols   []string `yaml:"out_of_order_reassembly_protocols,omitempty"`
	SegmentationReassemblyProtocols []string `yaml:"segmentation_reassembly_protocols,omitempty"`
}

type EbpfFileIoEvent struct {
	CollectMode     int    `yaml:"collect_mode,omitempty"`
	MinimalDuration string `yaml:"minimal_duration,omitempty"`
}

type EbpfFile struct {
	IoEvent EbpfFileIoEvent `yaml:"io_event,omitempty"`
}

type EbpfProfileOnCpu struct {
	Disabled          bool `yaml:"disabled,omitempty"`
	SamplingFrequency int  `yaml:"sampling_frequency,omitempty"`
	AggregateByCpu    bool `yaml:"aggregate_by_cpu,omitempty"`
}

type EbpfProfileOffCpu struct {
	Disabled        bool   `yaml:"disabled,omitempty"`
	AggregateByCpu  bool   `yaml:"aggregate_by_cpu,omitempty"`
	MinBlockingTime string `yaml:"min_blocking_time,omitempty"`
}

type EbpfProfileMemory struct {
	Disabled       bool   `yaml:"disabled,omitempty"`
	ReportInterval string `yaml:"report_interval,omitempty"`
}

type EbpfProfilePreprocess struct {
	StackCompression bool `yaml:"stack_compression,omitempty"`
}

type EbpfProfileUnwinding struct {
	DwarfDisabled       bool   `yaml:"dwarf_disabled,omitempty"`
	DwarfRegex          string `yaml:"dwarf_regex,omitempty"`
	DwarfProcessMapSize int    `yaml:"dwarf_process_map_size,omitempty"`
	DwarfShardMapSize   int    `yaml:"dwarf_shard_map_size,omitempty"`
}

type EbpfProfile struct {
	Unwinding  EbpfProfileUnwinding  `yaml:"unwinding,omitempty"`
	OnCpu      EbpfProfileOnCpu      `yaml:"on_cpu,omitempty"`
	OffCpu     EbpfProfileOffCpu     `yaml:"off_cpu,omitempty"`
	Memory     EbpfProfileMemory     `yaml:"memory,omitempty"`
	Preprocess EbpfProfilePreprocess `yaml:"preprocess,omitempty"`
}

type EbpfTunning struct {
	CollectorQueueSize        int `yaml:"collector_queue_size,omitempty"`
	UserspaceWorkerThreads    int `yaml:"userspace_worker_threads,omitempty"`
	PerfPagesCount            int `yaml:"perf_pages_count,omitempty"`
	KernelRingSize            int `yaml:"kernel_ring_size,omitempty"`
	MaxSocketEntries          int `yaml:"max_socket_entries,omitempty"`
	SocketMapReclaimThreshold int `yaml:"socket_map_reclaim_threshold,omitempty"`
	MaxTraceEntries           int `yaml:"max_trace_entries,omitempty"`
}

type Resources struct {
	PushInterval               string                     `yaml:"push_interval,omitempty"`
	PrivateCloud               PrivateCloud               `yaml:"private_cloud,omitempty"`
	Kubernetes                 Kubernetes                 `yaml:"kubernetes,omitempty"`
	PullResourceFromController PullResourceFromController `yaml:"pull_resource_from_controller,omitempty"`
}

type PrivateCloud struct {
	HypervisorResourceEnabled bool   `yaml:"hypervisor_resource_enabled,omitempty"`
	VmMacSource               int    `yaml:"vm_mac_source,omitempty"`
	VmXmlDirectory            string `yaml:"vm_xml_directory,omitempty"`
	VmMacMappingScript        string `yaml:"vm_mac_mapping_script,omitempty"`
}

type Kubernetes struct {
	KubernetesNamespace    string         `yaml:"kubernetes_namespace,omitempty"`
	ApiResources           []ApiResources `yaml:"api_resources,omitempty"`
	ApiListPageSize        int            `yaml:"api_list_page_size,omitempty"`
	ApiListMaxInterval     string         `yaml:"api_list_max_interval,omitempty"`
	IngressFlavour         string         `yaml:"ingress_flavour,omitempty"`
	PodMacCollectionMethod string         `yaml:"pod_mac_collection_method,omitempty"`
}

type ApiResources struct {
	Name string `yaml:"name,omitempty"`
}

type PullResourceFromController struct {
	DomainFilter                      []string `yaml:"domain_filter,omitempty"`
	OnlyKubernetesPodIPInLocalCluster bool     `yaml:"only_kubernetes_pod_ip_in_local_cluster,omitempty"`
}

type Integration struct {
	Enabled               bool                   `yaml:"enabled,omitempty"`
	ListenPort            int                    `yaml:"listen_port,omitempty"`
	Compression           IntegrationCompression `yaml:"compression,omitempty"`
	PrometheusExtraLabels PrometheusExtraLabels  `yaml:"prometheus_extra_labels,omitempty"`
	FeatureControl        FeatureControl         `yaml:"feature_control,omitempty"`
}

type IntegrationCompression struct {
	Trace   bool `yaml:"trace,omitempty"`
	Profile bool `yaml:"profile,omitempty"`
}

type PrometheusExtraLabels struct {
	Enabled     bool     `yaml:"enabled,omitempty"`
	ExtraLabels []string `yaml:"extra_labels,omitempty"`
	LabelLength int      `yaml:"label_length,omitempty"`
	ValueLength int      `yaml:"value_length,omitempty"`
}

type FeatureControl struct {
	ProfileIntegrationDisabled bool `yaml:"profile_integration_disabled,omitempty"`
	TraceIntegrationDisabled   bool `yaml:"trace_integration_disabled,omitempty"`
	MetricIntegrationDisabled  bool `yaml:"metric_integration_disabled,omitempty"`
	LogIntegrationDisabled     bool `yaml:"log_integration_disabled,omitempty"`
}

type Processors struct {
	Packet     Packet            `yaml:"packet,omitempty"`
	RequestLog RequestLog        `yaml:"request_log,omitempty"`
	FlowLog    ProcessorsFlowLog `yaml:"flow_log,omitempty"`
}

type Packet struct {
	Policy     Policy     `yaml:"policy,omitempty"`
	TcpHeader  TcpHeader  `yaml:"tcp_header,omitempty"`
	PcapStream PcapStream `yaml:"pcap_stream,omitempty"`
	Toa        Toa        `yaml:"toa,omitempty"`
}

type Policy struct {
	FastPathMapSize      int  `yaml:"fast_path_map_size,omitempty"`
	FastPathDisabled     bool `yaml:"fast_path_disabled,omitempty"`
	ForwardTableCapacity int  `yaml:"forward_table_capacity,omitempty"`
	MaxFirstPathLevel    int  `yaml:"max_first_path_level,omitempty"`
}

type TcpHeader struct {
	BlockSize        int `yaml:"block_size,omitempty"`
	SenderQueueSize  int `yaml:"sender_queue_size,omitempty"`
	SenderQueueCount int `yaml:"sender_queue_count,omitempty"`
	HeaderFieldsFlag int `yaml:"header_fields_flag,omitempty"`
}

type PcapStream struct {
	ReceiverQueueSize int    `yaml:"receiver_queue_size,omitempty"`
	BufferSizePerFlow int    `yaml:"buffer_size_per_flow,omitempty"`
	TotalBufferSize   int    `yaml:"total_buffer_size,omitempty"`
	FlushInterval     string `yaml:"flush_interval,omitempty"` // Duration will be represented as a string
}

type Toa struct {
	SenderQueueSize int `yaml:"sender_queue_size,omitempty"`
	CacheSize       int `yaml:"cache_size,omitempty"`
}

type RequestLog struct {
	ApplicationProtocolInference ApplicationProtocolInference `yaml:"application_protocol_inference,omitempty"`
	Filters                      Filters                      `yaml:"filters,omitempty"`
	Timeouts                     Timeouts                     `yaml:"timeouts,omitempty"`
	TagExtraction                RequestLogTagExtraction      `yaml:"tag_extraction,omitempty"`
	Tunning                      RequestLogTunning            `yaml:"tunning,omitempty"`
}

type ApplicationProtocolInference struct {
	InferenceMaxRetries   int                   `yaml:"inference_max_retries,omitempty"`
	InferenceResultTTL    string                `yaml:"inference_result_ttl,omitempty"`
	EnabledProtocols      []string              `yaml:"enabled_protocols,omitempty"`
	ProtocolSpecialConfig ProtocolSpecialConfig `yaml:"protocol_special_config,omitempty"`
}

type ProtocolSpecialConfig struct {
	Oracle OracleProtoConfig `yaml:"oracle,omitempty"`
}

type OracleProtoConfig struct {
	IsBE              bool `yaml:"is_be,omitempty"`
	IntCompressed     bool `yaml:"int_compressed,omitempty"`
	Resp0x04ExtraByte bool `yaml:"resp_0x04_extra_byte,omitempty"`
}

type Filters struct {
	PortNumberPrefilters                   PortNumberPrefilters `yaml:"port_number_prefilters,omitempty"`
	TagFilters                             TagFilters           `yaml:"tag_filters,omitempty"`
	UnconcernedDNSNXDomainResponseSuffixes []string             `yaml:"unconcerned_dns_nxdomain_response_suffixes,omitempty"`
}

type PortNumberPrefilters struct {
	HTTP       string `yaml:"HTTP,omitempty"`
	HTTP2      string `yaml:"HTTP2,omitempty"`
	Dubbo      string `yaml:"Dubbo,omitempty"`
	SofaRPC    string `yaml:"SofaRPC,omitempty"`
	FastCGI    string `yaml:"FastCGI,omitempty"`
	BRPC       string `yaml:"bRPC,omitempty"`
	Tars       string `yaml:"Tars,omitempty"`
	SomeIP     string `yaml:"SomeIP,omitempty"`
	MySQL      string `yaml:"MySQL,omitempty"`
	PostgreSQL string `yaml:"PostgreSQL,omitempty"`
	Oracle     string `yaml:"Oracle,omitempty"`
	Redis      string `yaml:"Redis,omitempty"`
	MongoDB    string `yaml:"MongoDB,omitempty"`
	Memcached  string `yaml:"Memcached,omitempty"`
	Kafka      string `yaml:"Kafka,omitempty"`
	MQTT       string `yaml:"MQTT,omitempty"`
	AMQP       string `yaml:"AMQP,omitempty"`
	OpenWire   string `yaml:"OpenWire,omitempty"`
	NATS       string `yaml:"NATS,omitempty"`
	Pulsar     string `yaml:"Pulsar,omitempty"`
	ZMTP       string `yaml:"ZMTP,omitempty"`
	DNS        string `yaml:"DNS,omitempty"`
	TLS        string `yaml:"TLS,omitempty"`
	Custom     string `yaml:"Custom,omitempty"`
}

type TagFilters struct {
	HTTP       []TagFilterOperator `yaml:"HTTP,omitempty"`
	HTTP2      []TagFilterOperator `yaml:"HTTP2,omitempty"`
	Dubbo      []TagFilterOperator `yaml:"Dubbo,omitempty"`
	GRPC       []TagFilterOperator `yaml:"gRpc,omitempty"`
	SofaRPC    []TagFilterOperator `yaml:"SofaRPC,omitempty"`
	FastCGI    []TagFilterOperator `yaml:"FastCGI,omitempty"`
	BRPC       []TagFilterOperator `yaml:"bRPC,omitempty"`
	Tars       []TagFilterOperator `yaml:"Tars,omitempty"`
	SomeIP     []TagFilterOperator `yaml:"SomeIP,omitempty"`
	MySQL      []TagFilterOperator `yaml:"MySQL,omitempty"`
	PostgreSQL []TagFilterOperator `yaml:"PostgreSQL,omitempty"`
	Oracle     []TagFilterOperator `yaml:"Oracle,omitempty"`
	Redis      []TagFilterOperator `yaml:"Redis,omitempty"`
	MongoDB    []TagFilterOperator `yaml:"MongoDB,omitempty"`
	Memcached  []TagFilterOperator `yaml:"Memcached,omitempty"`
	Kafka      []TagFilterOperator `yaml:"Kafka,omitempty"`
	MQTT       []TagFilterOperator `yaml:"MQTT,omitempty"`
	AMQP       []TagFilterOperator `yaml:"AMQP,omitempty"`
	OpenWire   []TagFilterOperator `yaml:"OpenWire,omitempty"`
	NATS       []TagFilterOperator `yaml:"NATS,omitempty"`
	Pulsar     []TagFilterOperator `yaml:"Pulsar,omitempty"`
	ZMTP       []TagFilterOperator `yaml:"ZMTP,omitempty"`
	DNS        []TagFilterOperator `yaml:"DNS,omitempty"`
	TLS        []TagFilterOperator `yaml:"TLS,omitempty"`
}

type TagFilterOperator struct {
	FieldName string `yaml:"field_name,omitempty"`
	Operator  string `yaml:"operator,omitempty"`
	Value     string `yaml:"value,omitempty"`
}

type Timeouts struct {
	TcpRequestTimeout              string `yaml:"tcp_request_timeout,omitempty"`
	UdpRequestTimeout              string `yaml:"udp_request_timeout,omitempty"`
	SessionAggregateWindowDuration string `yaml:"session_aggregate_window_duration,omitempty"`
}

type RequestLogTagExtraction struct {
	TracingTag         TracingTag   `yaml:"tracing_tag,omitempty"`
	HttpEndpoint       HttpEndpoint `yaml:"http_endpoint,omitempty"`
	CustomFields       CustomFields `yaml:"custom_fields,omitempty"`
	ObfuscateProtocols []string     `yaml:"obfuscate_protocols,omitempty"`
}

type TracingTag struct {
	HttpRealClient string   `yaml:"http_real_client,omitempty"`
	XRequestID     string   `yaml:"x_request_id,omitempty"`
	ApmTraceID     []string `yaml:"apm_trace_id,omitempty"`
	ApmSpanID      []string `yaml:"apm_span_id,omitempty"`
}

type HttpEndpoint struct {
	ExtractionDisabled bool                    `yaml:"extraction_disabled,omitempty"`
	MatchRules         []HttpEndpointMatchRule `yaml:"match_rules,omitempty"`
}

type HttpEndpointMatchRule struct {
	UrlPrefix    string `yaml:"url_prefix,omitempty"`
	KeepSegments int    `yaml:"keep_segments,omitempty"`
}

type CustomFields struct {
	Http  []CustomFieldsInfo `yaml:"http,omitempty"`
	Http2 []CustomFieldsInfo `yaml:"http2,omitempty"`
}

type CustomFieldsInfo struct {
	FieldName string `yaml:"field_name,omitempty"`
}

type RequestLogTunning struct {
	PayloadTruncation              int  `yaml:"payload_truncation,omitempty"`
	SessionAggregateSlotCapacity   int  `yaml:"session_aggregate_slot_capacity,omitempty"`
	ConsistentTimestampInL7Metrics bool `yaml:"consistent_timestamp_in_l7_metrics,omitempty"`
}

type ProcessorsFlowLog struct {
	TimeWindow TimeWindow               `yaml:"time_window,omitempty"`
	Conntrack  Conntrack                `yaml:"conntrack,omitempty"`
	Tunning    ProcessorsFlowLogTunning `yaml:"tunning,omitempty"`
}

type TimeWindow struct {
	MaxTolerablePacketDelay string `yaml:"max_tolerable_packet_delay,omitempty"`
	ExtraTolerableFlowDelay string `yaml:"extra_tolerable_flow_delay,omitempty"`
}

type Conntrack struct {
	FlowFlushInterval string            `yaml:"flow_flush_interval,omitempty"`
	FlowGeneration    FlowGeneration    `yaml:"flow_generation,omitempty"`
	Timeouts          ConntrackTimeouts `yaml:"timeouts,omitempty"`
}

type FlowGeneration struct {
	ServerPorts           []int `yaml:"server_ports,omitempty"`
	CloudTrafficIgnoreMac bool  `yaml:"cloud_traffic_ignore_mac,omitempty"`
	IgnoreL2End           bool  `yaml:"ignore_l2_end,omitempty"`
	IdcTrafficIgnoreVlan  bool  `yaml:"idc_traffic_ignore_vlan,omitempty"`
}

type ConntrackTimeouts struct {
	Established string `yaml:"established,omitempty"`
	ClosingRst  string `yaml:"closing_rst,omitempty"`
	OpeningRst  string `yaml:"opening_rst,omitempty"`
	Others      string `yaml:"others,omitempty"`
}

type ProcessorsFlowLogTunning struct {
	FlowMapHashSlots            int `yaml:"flow_map_hash_slots,omitempty"`
	ConcurrentFlowLimit         int `yaml:"concurrent_flow_limit,omitempty"`
	MemoryPoolSize              int `yaml:"memory_pool_size,omitempty"`
	MaxBatchedBufferSize        int `yaml:"max_batched_buffer_size,omitempty"`
	FlowAggregatorQueueSize     int `yaml:"flow_aggregator_queue_size,omitempty"`
	FlowGeneratorQueueSize      int `yaml:"flow_generator_queue_size,omitempty"`
	QuadrupleGeneratorQueueSize int `yaml:"quadruple_generator_queue_size,omitempty"`
}

type Outputs struct {
	Socket      Socket         `yaml:"socket,omitempty"`
	FlowLog     OutputsFlowLog `yaml:"flow_log,omitempty"`
	FlowMetrics FlowMetrics    `yaml:"flow_metrics,omitempty"`
	Npb         Npb            `yaml:"npb,omitempty"`
}

type Socket struct {
	DataSocketType            string `yaml:"data_socket_type,omitempty"`
	NpbSocketType             string `yaml:"npb_socket_type,omitempty"`
	RawUdpQosBypass           bool   `yaml:"raw_udp_qos_bypass,omitempty"`
	MultipleSocketsToIngester bool   `yaml:"multiple_sockets_to_ingester,omitempty"`
}

type OutputsFlowLog struct {
	Filters   FlowLogFilters        `yaml:"filters,omitempty"`
	Throttles Throttles             `yaml:"throttles,omitempty"`
	Tunning   OutputsFlowLogTunning `yaml:"tunning,omitempty"`
}

type FlowLogFilters struct {
	L4CaptureNetworkTypes      []int `yaml:"l4_capture_network_types,omitempty"`
	L7CaptureNetworkTypes      []int `yaml:"l7_capture_network_types,omitempty"`
	L4IgnoredObservationPoints []int `yaml:"l4_ignored_observation_points,omitempty"`
	L7IgnoredObservationPoints []int `yaml:"l7_ignored_observation_points,omitempty"`
}

type Throttles struct {
	L4Throttle int `yaml:"l4_throttle,omitempty"`
	L7Throttle int `yaml:"l7_throttle,omitempty"`
}

type OutputsFlowLogTunning struct {
	CollectorQueueSize  int `yaml:"collector_queue_size,omitempty"`
	CollectorQueueCount int `yaml:"collector_queue_count,omitempty"`
}

type FlowMetricsFilters struct {
	InactiveServerPortAggregation bool `yaml:"inactive_server_port_aggregation,omitempty"`
	InactiveIpAggregation         bool `yaml:"inactive_ip_aggregation,omitempty"`
	NpmMetrics                    bool `yaml:"npm_metrics,omitempty"`
	ApmMetrics                    bool `yaml:"apm_metrics,omitempty"`
	SecondMetrics                 bool `yaml:"second_metrics,omitempty"`
}

type FlowMetricsTunning struct {
	SenderQueueSize  int `yaml:"sender_queue_size,omitempty"`
	SenderQueueCount int `yaml:"sender_queue_count,omitempty"`
}

type FlowMetrics struct {
	Enabled bool               `yaml:"enabled,omitempty"`
	Filters FlowMetricsFilters `yaml:"filters,omitempty"`
	Tunning FlowMetricsTunning `yaml:"tunning,omitempty"`
}

type Npb struct {
	MaxMtu                    int  `yaml:"max_mtu,omitempty"`
	RawUdpVlanTag             int  `yaml:"raw_udp_vlan_tag,omitempty"`
	ExtraVlanHeader           int  `yaml:"extra_vlan_header,omitempty"`
	TrafficGlobalDedup        bool `yaml:"traffic_global_dedup,omitempty"`
	TargetPort                int  `yaml:"target_port,omitempty"`
	CustomVxlanFlags          int8 `yaml:"custom_vxlan_flags,omitempty"`
	OverlayVlanHeaderTrimming bool `yaml:"overlay_vlan_header_trimming,omitempty"`
	MaxTxThroughput           int  `yaml:"max_tx_throughput,omitempty"`
}

type Plugins struct {
	UpdateTime  string   `yaml:"update_time,omitempty"`
	WasmPlugins []string `yaml:"wasm_plugins,omitempty"`
	SoPlugins   []string `yaml:"so_plugins,omitempty"`
}

type Dev struct {
	FeatureFlags []string `yaml:"feature_flags,omitempty"`
}
