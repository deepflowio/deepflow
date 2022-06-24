package model

type StaticConfig struct {
	ControllerIps                   []string              `yaml:"controller-ips,omitempty"`
	ControllerPort                  *uint16               `yaml:"controller-port,omitempty"`
	ControllerTLSPort               *uint16               `yaml:"controller-tls-port,omitempty"`
	GenesisRpcPort                  *uint16               `yaml:"genesis-rpc-port,omitempty"`
	GenesisRpcTLSPort               *uint16               `yaml:"genesis-rpc-tls-port,omitempty"`
	Logfile                         *string               `yaml:"log-file,omitempty"`
	LogLevel                        *string               `yaml:"log-level,omitempty"`
	Profiler                        *bool                 `yaml:"profiler,omitempty"`
	AfpacketBlocksEnabled           *bool                 `yaml:"afpacket-blocks-enabled,omitempty"`
	AfpacketBlocks                  *int                  `yaml:"afpacket-blocks,omitempty"`
	EnableDebugStats                *bool                 `yaml:"enable-debug-stats,omitempty"`
	AnalyzerDedupDisabled           *bool                 `yaml:"analyzer-dedup-disabled,omitempty"`
	DefaultTapType                  *uint32               `yaml:"default-tap-type,omitempty"`
	DebugListenPort                 *uint16               `yaml:"debug-listen-port,omitempty"`
	EnableQosBypass                 *bool                 `yaml:"enable-qos-bypass,omitempty"`
	FastPathMapSize                 *int                  `yaml:"fast-path-map-size,omitempty"`
	FirstPathLevel                  *int                  `yaml:"first-path-level,omitempty"`
	SrcInterfaces                   []string              `yaml:"src-interfaces,omitempty"`
	TapMode                         *int                  `yaml:"tap-mode,omitempty"`
	CloudGatewayTraffic             *bool                 `yaml:"cloud-gateway-traffic,omitempty"`
	MirrorTrafficPcp                *uint16               `yaml:"mirror-traffic-pcp,omitempty"`
	ControllerCertFilePrefix        *string               `yaml:"controller-cert-file-prefix,omitempty"`
	VtapGroupIdRequest              *string               `yaml:"vtap-group-id-request,omitempty"`
	PCap                            *PCapConfig           `yaml:"pcap,omitempty"`
	Flow                            *FlowGeneratorConfig  `yaml:"flow,omitempty"`
	FlowQueueSize                   *int                  `yaml:"flow-queue-size,omitempty"`
	QuadrupleQueueSize              *int                  `yaml:"quadruple-queue-size,omitempty"`
	AnalyzerQueueSize               *int                  `yaml:"analyzer-queue-size,omitempty"`
	OvsDpdkEnable                   *bool                 `yaml:"ovs-dpdk-enable,omitempty"`
	DpdkPmdCoreId                   *uint32               `yaml:"dpdk-pmd-core-id,omitempty"`
	DpdkRingPort                    *string               `yaml:"dpdk-ring-port,omitempty"`
	XflowCollector                  *XflowCollectorConfig `yaml:"xflow-collector,omitempty"`
	VxlanPort                       *uint16               `yaml:"vxlan-port,omitempty"`
	VxlanFlags                      *uint8                `yaml:"vxlan-flags,omitempty"`
	CollectorSenderQueueSize        *int                  `yaml:"collector-sender-queue-size,omitempty"`
	CollectorSenderQueueCount       *int                  `yaml:"collector-sender-queue-count,omitempty"`
	FlowSenderQueueSize             *int                  `yaml:"flow-sender-queue-size,omitempty"`
	FlowSenderQueueCount            *int                  `yaml:"flow-sender-queue-count,omitempty"`
	SecondFlowExtraDelaySecond      *int                  `yaml:"second-flow-extra-delay-second,omitempty"`
	PacketDelay                     *int                  `yaml:"packet-delay,omitempty"`
	Triple                          *TripleMapConfig      `yaml:"triple,omitempty"`
	KubernetesPollerType            *string               `yaml:"kubernetes-poller-type,omitempty"`
	DecapErspan                     *bool                 `yaml:"decap-erspan,omitempty"`
	AnalyzerIp                      *string               `yaml:"analyzer-ip,omitempty"`
	KubernetesClusterID             *string               `yaml:"kubernetes-cluster-id,omitempty"`
	KubernetesNamespace             *string               `yaml:"kubernetes-namespace,omitempty"`
	IngressFlavour                  *string               `yaml:"ingress-flavour,omitempty"`
	GrpcBufferSize                  *int                  `yaml:"grpc-buffer-size,omitempty"`            // 单位：M
	L7LogSessionAggrTimeout         *int                  `yaml:"l7-log-session-aggr-timeout,omitempty"` // 单位: s
	TapMacScript                    *string               `yaml:"tap-mac-script,omitempty"`
	BpfDisabled                     *bool                 `yaml:"bpf-disabled,omitempty"`
	L7ProtocolInferenceMaxFailCount *uint64               `yaml:"l7-protocol-inference-max-fail-count,omitempty"`
	L7ProtocolInferenceTtl          *uint64               `yaml:"l7-protocol-inference-ttl,omitempty"`
}

type XflowCollectorConfig struct {
	SflowPorts   []string `yaml:"sflow-ports,omitempty"`
	NetflowPorts []string `yaml:"netflow-ports,omitempty"`
}

type PCapConfig struct {
	Enabled               *bool   `yaml:"enabled,omitempty"`
	QueueSize             *int    `yaml:"queue-size,omitempty"`
	QueueCount            *int    `yaml:"queue-count,omitempty"`
	TCPIPChecksum         *bool   `yaml:"tcpip-checksum,omitempty"`
	BlockSizeKB           *int    `yaml:"block-size-kb,omitempty"`
	MaxConcurrentFiles    *int    `yaml:"max-concurrent-files,omitempty"`
	MaxFileSizeMB         *int    `yaml:"max-file-size-mb,omitempty"`
	MaxDirectorySizeGb    *int    `yaml:"max-directory-size-gb,omitempty"`
	DiskFreeSpaceMarginGb *int    `yaml:"disk-free-space-margin-gb,omitempty"`
	MaxFilePeriodSecond   *int    `yaml:"max-file-period-second,omitempty"`
	FileDirectory         *string `yaml:"file-directory,omitempty"`
	ServerPort            *int    `yaml:"server-port,omitempty"`
}

type TripleMapConfig struct {
	HashSlots *int `yaml:"hash-slots-size,omitempty"`
	Capacity  *int `yaml:"capacity,omitempty"`
}

type TcpTimeoutConfig struct {
	EstablishedTimeout *int `yaml:"established-timeout,omitempty"`
	ClosingRstTimeout  *int `yaml:"closing-rst-timeout,omitempty"`
	OthersTimeout      *int `yaml:"others-timeout,omitempty"`
}

type FlowGeneratorConfig struct {
	TcpTimeoutConfig `yaml:",inline"`
	HashSlots        *int `yaml:"flow-slots-size,omitempty"`
	Capacity         *int `yaml:"flow-count-limit,omitempty"`
	FlushInterval    *int `yaml:"flush-interval,omitempty"`
	SenderThrottle   *int `yaml:"flow-sender-throttle,omitempty"`
	AggrQueueSize    *int `yaml:"flow-aggr-queue-size,omitempty"`

	IgnoreTorMac *bool `yaml:"ignore-tor-mac,omitempty"`
	IgnoreL2End  *bool `yaml:"ignore-l2-end,omitempty"`
}
