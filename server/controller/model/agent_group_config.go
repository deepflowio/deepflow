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

import _ "embed"

//go:embed agent_group_config_example.yaml
var YamlAgentGroupConfig []byte

type StaticConfig struct {
	ProxyControllerPort                *uint16                     `yaml:"proxy-controller-port,omitempty"`
	LogLevel                           *string                     `yaml:"log-level,omitempty"`
	Profiler                           *bool                       `yaml:"profiler,omitempty"`
	AfpacketBlocksEnabled              *bool                       `yaml:"afpacket-blocks-enabled,omitempty"`
	AfpacketBlocks                     *int                        `yaml:"afpacket-blocks,omitempty"`
	AnalyzerRawPacketBlockSize         *int                        `yaml:"analyzer-raw-packet-block-size,omitempty"`
	BatchedBufferSizeLimit             *int                        `yaml:"batched-buffer-size-limit,omitempty"`
	EnableDebugStats                   *bool                       `yaml:"enable-debug-stats,omitempty"`
	AnalyzerDedupDisabled              *bool                       `yaml:"analyzer-dedup-disabled,omitempty"`
	DefaultTapType                     *uint32                     `yaml:"default-tap-type,omitempty"`
	DebugListenPort                    *uint16                     `yaml:"debug-listen-port,omitempty"`
	EnableQosBypass                    *bool                       `yaml:"enable-qos-bypass,omitempty"`
	FastPathMapSize                    *int                        `yaml:"fast-path-map-size,omitempty"`
	FirstPathLevel                     *int                        `yaml:"first-path-level,omitempty"`
	SrcInterfaces                      []string                    `yaml:"src-interfaces,omitempty"`
	CloudGatewayTraffic                *bool                       `yaml:"cloud-gateway-traffic,omitempty"`
	MirrorTrafficPcp                   *uint16                     `yaml:"mirror-traffic-pcp,omitempty"`
	PCap                               *PCapConfig                 `yaml:"pcap,omitempty"`
	Flow                               *FlowGeneratorConfig        `yaml:"flow,omitempty"`
	FlowQueueSize                      *int                        `yaml:"flow-queue-size,omitempty"`
	QuadrupleQueueSize                 *int                        `yaml:"quadruple-queue-size,omitempty"`
	AnalyzerQueueSize                  *int                        `yaml:"analyzer-queue-size,omitempty"`
	OvsDpdkEnable                      *bool                       `yaml:"ovs-dpdk-enable,omitempty"`
	DpdkPmdCoreId                      *uint32                     `yaml:"dpdk-pmd-core-id,omitempty"`
	DpdkRingPort                       *string                     `yaml:"dpdk-ring-port,omitempty"`
	LibpcapEnabled                     *bool                       `yaml:"libpcap-enabled,omitempty"`
	XflowCollector                     *XflowCollectorConfig       `yaml:"xflow-collector,omitempty"`
	NpbPort                            *uint16                     `yaml:"npb-port,omitempty"`
	VxlanFlags                         *uint8                      `yaml:"vxlan-flags,omitempty"`
	CollectorSenderQueueSize           *int                        `yaml:"collector-sender-queue-size,omitempty"`
	CollectorSenderQueueCount          *int                        `yaml:"collector-sender-queue-count,omitempty"`
	ToaSenderQueueSize                 *int                        `yaml:"toa-sender-queue-size,omitempty"`
	ToaLruCacheSize                    *int                        `yaml:"toa-lru-cache-size,omitempty"`
	FlowSenderQueueSize                *int                        `yaml:"flow-sender-queue-size,omitempty"`
	FlowSenderQueueCount               *int                        `yaml:"flow-sender-queue-count,omitempty"`
	SecondFlowExtraDelaySecond         *string                     `yaml:"second-flow-extra-delay-second,omitempty"`
	PacketDelay                        *string                     `yaml:"packet-delay,omitempty"`
	Triple                             *TripleMapConfig            `yaml:"triple,omitempty"`
	KubernetesPollerType               *string                     `yaml:"kubernetes-poller-type,omitempty"`
	DecapErspan                        *bool                       `yaml:"decap-erspan,omitempty"`
	AnalyzerIp                         *string                     `yaml:"analyzer-ip,omitempty"`
	AnalyzerPort                       *uint16                     `yaml:"analyzer-port,omitempty"`
	KubernetesNamespace                *string                     `yaml:"kubernetes-namespace,omitempty"`
	KubernetesAPIListLimit             *uint32                     `yaml:"kubernetes-api-list-limit,omitempty"`
	KubernetesAPIListInterval          *string                     `yaml:"kubernetes-api-list-interval,omitempty"`
	KubernetesResources                []KubernetesResourceConfig  `yaml:"kubernetes-resources,omitempty"`
	IngressFlavour                     *string                     `yaml:"ingress-flavour,omitempty"`
	GrpcBufferSize                     *int                        `yaml:"grpc-buffer-size,omitempty"`            // 单位：M
	L7LogSessionAggrTimeout            *string                     `yaml:"l7-log-session-aggr-timeout,omitempty"` // 单位: s
	TapMacScript                       *string                     `yaml:"tap-mac-script,omitempty"`
	BpfDisabled                        *bool                       `yaml:"bpf-disabled,omitempty"`
	L7ProtocolInferenceMaxFailCount    *uint64                     `yaml:"l7-protocol-inference-max-fail-count,omitempty"`
	L7ProtocolInferenceTtl             *uint64                     `yaml:"l7-protocol-inference-ttl,omitempty"`
	PacketSequenceBlockSize            *int                        `yaml:"packet-sequence-block-size,omitempty"`
	PacketSequenceQueueSize            *int                        `yaml:"packet-sequence-queue-size,omitempty"`
	PacketSequenceQueueCount           *int                        `yaml:"packet-sequence-queue-count,omitempty"`
	PacketSequenceFlag                 *uint8                      `yaml:"packet-sequence-flag,omitempty"`
	L7ProtocolEnabled                  []string                    `yaml:"l7-protocol-enabled,omitempty"`
	StandaloneDataFileSize             *uint64                     `yaml:"standalone-data-file-size,omitempty"`
	StandaloneDataFileDir              *string                     `yaml:"standalone-data-file-dir,omitempty"`
	LogFile                            *string                     `yaml:"log-file,omitempty"`
	ExternalAgentHttpProxyCompressed   *bool                       `yaml:"external-agent-http-proxy-compressed,omitempty"`
	FeatureFlags                       []string                    `yaml:"feature-flags,omitempty"`
	L7ProtocolPorts                    map[string]string           `yaml:"l7-protocol-ports,omitempty"`
	L7ProtocolAdvancedFeatures         *L7ProtocolAdvancedFeatures `yaml:"l7-protocol-advanced-features,omitempty"`
	Ebpf                               *EbpfConfig                 `yaml:"ebpf,omitempty"`
	OsAppTagExecUser                   *string                     `yaml:"os-app-tag-exec-user,omitempty"`
	OsAppTagExec                       []string                    `yaml:"os-app-tag-exec,omitempty"`
	OsProcRoot                         *string                     `yaml:"os-proc-root,omitempty"`
	OsProcSocketSyncInterval           *int                        `yaml:"os-proc-socket-sync-interval,omitempty"`
	OsProcSocketMinLifetime            *int                        `yaml:"os-proc-socket-min-lifetime,omitempty"`
	OsProcRegex                        []*OsProcRegex              `yaml:"os-proc-regex,omitempty"`
	OsProcSyncEnabled                  *bool                       `yaml:"os-proc-sync-enabled,omitempty"`
	OsProcSyncTaggedOnly               *bool                       `yaml:"os-proc-sync-tagged-only,omitempty"`
	GuardInterval                      *string                     `yaml:"guard-interval,omitempty"`
	CheckCoreFileDisabled              *bool                       `yaml:"check-core-file-disabled,omitempty"`
	WasmPlugins                        []string                    `yaml:"wasm-plugins,omitempty"`
	SoPlugins                          []string                    `yaml:"so-plugins,omitempty"`
	MemoryTrimDisabled                 *bool                       `yaml:"memory-trim-disabled,omitempty"`
	FastPathDisabled                   *bool                       `yaml:"fast-path-disabled,omitempty"`
	ForwardCapacity                    *uint32                     `yaml:"forward-capacity,omitempty"`
	RrtTcpTimeout                      *string                     `yaml:"rrt-tcp-timeout,omitempty"`
	RrtUdpTimeout                      *string                     `yaml:"rrt-udp-timeout,omitempty"`
	PrometheusExtraConfig              *PrometheusExtraConfig      `yaml:"prometheus-extra-config,omitempty"`
	ProcessSchedulingPriority          *int8                       `yaml:"process-scheduling-priority,omitempty"`
	CpuAffinity                        *string                     `yaml:"cpu-affinity,omitempty"`
	ExternalProfileIntegrationDisabled *bool                       `yaml:"external-profile-integration-disabled,omitempty"`
	ExternalTraceIntegrationDisabled   *bool                       `yaml:"external-trace-integration-disabled,omitempty"`
	ExternalMetricIntegrationDisabled  *bool                       `yaml:"external-metric-integration-disabled,omitempty"`
	NtpMaxInterval                     *string                     `yaml:"ntp-max-interval,omitempty"`
	NtpMinInterval                     *string                     `yaml:"ntp-min-interval,omitempty"`
}

type XflowCollectorConfig struct {
	SflowPorts   []string `yaml:"sflow-ports,omitempty"`
	NetflowPorts []string `yaml:"netflow-ports,omitempty"`
}

type PCapConfig struct {
	QueueSize      *int    `yaml:"queue-size,omitempty"`
	QueueCount     *int    `yaml:"queue-count,omitempty"`
	FlowBufferSize *int    `yaml:"flow-buffer-size,omitempty"`
	BufferSize     *int    `yaml:"buffer-size,omitempty"`
	FlushInterval  *string `yaml:"flush-interval,omitempty"`
}

type TripleMapConfig struct {
	HashSlots *int `yaml:"hash-slots-size,omitempty"`
	Capacity  *int `yaml:"capacity,omitempty"`
}

type TcpTimeoutConfig struct {
	EstablishedTimeout *string `yaml:"established-timeout,omitempty"`
	ClosingRstTimeout  *string `yaml:"closing-rst-timeout,omitempty"`
	OthersTimeout      *string `yaml:"others-timeout,omitempty"`
	OpeningRstTimeout  *string `yaml:"opening-rst-timeout,omitempty"`
}

type FlowGeneratorConfig struct {
	TcpTimeoutConfig `yaml:",inline"`
	HashSlots        *int    `yaml:"flow-slots-size,omitempty"`
	Capacity         *int    `yaml:"flow-count-limit,omitempty"`
	FlushInterval    *string `yaml:"flush-interval,omitempty"`
	AggrQueueSize    *int    `yaml:"flow-aggr-queue-size,omitempty"`
	MemoryPoolSize   *int    `yaml:"memory-pool-size,omitempty"`

	IgnoreTorMac  *bool `yaml:"ignore-tor-mac,omitempty"`
	IgnoreL2End   *bool `yaml:"ignore-l2-end,omitempty"`
	IgnoreIdcVlan *bool `yaml:"ignore-idc-vlan,omitempty"`
}

type EbpfUprobeProcessNameRegexsConfig struct {
	GolangSymbol *string `yaml:"golang-symbol,omitempty"`
	Golang       *string `yaml:"golang,omitempty"`
	Openssl      *string `yaml:"openssl,omitempty"`
}

type EbpfKprobePortlist struct {
	PortList string `yaml:"port-list,omitempty"`
}

type OnCpuProfile struct {
	Disabled                           *bool   `yaml:"disabled,omitempty"`
	Frequency                          *int    `yaml:"frequency,omitempty"`
	Cpu                                *int    `yaml:"cpu,omitempty"`
	Regex                              *string `yaml:"regex,omitempty"`
	JavaSymbolFileMaxSpaceLimit        *int    `yaml:"java-symbol-file-max-space-limit,omitempty"`
	JavaSymbolFileRefreshDeferInterval *string `yaml:"java-symbol-file-refresh-defer-interval,omitempty"`
}

type EbpfConfig struct {
	Disabled                *bool                              `yaml:"disabled,omitempty"`
	LogFile                 *string                            `yaml:"log-file,omitempty"`
	UprobeProcessNameRegexs *EbpfUprobeProcessNameRegexsConfig `yaml:"uprobe-process-name-regexs,omitempty"`
	KprobeWhitelist         *EbpfKprobePortlist                `yaml:"kprobe-whitelist,omitempty"`
	KprobeBlacklist         *EbpfKprobePortlist                `yaml:"kprobe-blacklist,omitempty"`
	ThreadNum               *int                               `yaml:"thread-num,omitempty"`
	PerfPagesCount          *int                               `yaml:"perf-pages-count,omitempty"`
	RingSize                *int                               `yaml:"ring-size,omitempty"`
	MaxSocketEntries        *int                               `yaml:"max-socket-entries,omitempty"`
	MaxTraceEntries         *int                               `yaml:"max-trace-entries,omitempty"`
	SocketMapMaxReclaim     *int                               `yaml:"socket-map-max-reclaim,omitempty"`
	GoTracingTimeout        *int                               `yaml:"go-tracing-timeout,omitempty"`
	IOEventCollectMode      *int                               `yaml:"io-event-collect-mode,omitempty"`
	IOEventMinimalDuration  *string                            `yaml:"io-event-minimal-duration,omitempty"`
	OnCpuProfile            *OnCpuProfile                      `yaml:"on-cpu-profile,omitempty"`
}

type OsProcRegex struct {
	MatchRegex  *string `yaml:"match-regex,omitempty"`
	MatchType   *string `yaml:"match-type,omitempty"`
	Action      *string `yaml:"action,omitempty"`
	RewriteName *string `yaml:"rewrite-name,omitempty"`
}

type PrometheusExtraConfig struct {
	Enabled     *bool    `yaml:"enabled,omitempty"`
	Labels      []string `yaml:"labels,omitempty"`
	LabelsLimit *int     `yaml:"labels-limit,omitempty"`
	ValuesLimit *int     `yaml:"values-limit,omitempty"`
}

type KubernetesResourceConfig struct {
	Name     *string `yaml:"name,omitempty"`
	Group    *string `yaml:"group,omitempty"`
	Version  *string `yaml:"version,omitempty"`
	Disabled *bool   `yaml:"disabled,omitempty"`
}

type MatchRule struct {
	Prefix       *string `yaml:"prefix,omitempty"`
	KeepSegments *int    `yaml:"keep-segments,omitempty"`
}
type HttpEndpointExtraction struct {
	Disabled   *bool       `yaml:"disabled,omitempty"`
	MatchRules []MatchRule `yaml:"match-rules,omitempty"`
}

type L7ProtocolAdvancedFeatures struct {
	HttpEndpointExtraction *HttpEndpointExtraction `yaml:"http-endpoint-extraction,omitempty"`
}
