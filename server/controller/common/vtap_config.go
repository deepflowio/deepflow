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

package common

import (
	"github.com/deepflowio/deepflow/server/agent_config"
)

var DefaultVTapGroupConfig = &agent_config.AgentGroupConfigModel{
	MaxCollectPps:                 &DefaultMaxCollectPps,
	MaxNpbBps:                     &DefaultMaxNpbBps,
	MaxCPUs:                       &DefaultMaxCPUs,
	MaxMemory:                     &DefaultMaxMemory,
	PlatformSyncInterval:          &DefaultPlatformSyncInterval,
	SyncInterval:                  &DefaultSyncInterval,
	StatsInterval:                 &DefaultStatsInterval,
	RsyslogEnabled:                &DefaultRsyslogEnabled,
	MaxTxBandwidth:                &DefaultMaxTxBandwidth,
	BandwidthProbeInterval:        &DefaultBandwidthProbeInterval,
	TapInterfaceRegex:             &DefaultTapInterfaceRegex,
	MaxEscapeSeconds:              &DefaultMaxEscapeSeconds,
	Mtu:                           &DefaultMtu,
	OutputVlan:                    &DefaultOutputVlan,
	CollectorSocketType:           &DefaultCollectorSocketType,
	CompressorSocketType:          &DefaultCompressorSocketType,
	NpbSocketType:                 &DefaultNpbSocketType,
	NpbVlanMode:                   &DefaultNpbVlanMode,
	CollectorEnabled:              &DefaultCollectorEnabled,
	VTapFlow1sEnabled:             &DefaultVTapFlow1sEnabled,
	L4LogTapTypes:                 &DefaultL4LogTapTypes,
	L4LogIgnoreTapSides:           &DefaultL4LogIgnoreTapSides,
	L7LogIgnoreTapSides:           &DefaultL7LogIgnoreTapSides,
	NpbDedupEnabled:               &DefaultNpbDedupEnabled,
	PlatformEnabled:               &DefaultPlatformEnabled,
	IfMacSource:                   &DefaultIfMacSource,
	VMXMLPath:                     &DefaultVMXMLPath,
	NatIPEnabled:                  &DefaultNatIPEnabled,
	CapturePacketSize:             &DefaultCapturePacketSize,
	InactiveServerPortEnabled:     &DefaultInactiveServerPortEnabled,
	InactiveIPEnabled:             &DefaultInactiveIPEnabled,
	LogThreshold:                  &DefaultLogThreshold,
	LogLevel:                      &DefaultLogLevel,
	LogRetention:                  &DefaultLogRetention,
	HTTPLogProxyClient:            &DefaultHTTPLogProxyClient,
	HTTPLogTraceID:                &DefaultHTTPLogTraceID,
	L7LogPacketSize:               &DefaultL7LogPacketSize,
	L4LogCollectNpsThreshold:      &DefaultL4LogCollectNpsThreshold,
	L7LogCollectNpsThreshold:      &DefaultL7LogCollectNpsThreshold,
	L7MetricsEnabled:              &DefaultL7MetricsEnabled,
	L7LogStoreTapTypes:            &DefaultL7LogStoreTapTypes,
	CaptureSocketType:             &DefaultCaptureSocketType,
	CaptureBpf:                    &DefaultCaptureBpf,
	TapMode:                       &DefaultTapMode,
	ThreadThreshold:               &DefaultThreadThreshold,
	ProcessThreshold:              &DefaultProcessThreshold,
	NtpEnabled:                    &DefaultNtpEnabled,
	L4PerformanceEnabled:          &DefaultL4PerformanceEnabled,
	PodClusterInternalIP:          &DefaultPodClusterInternalIP,
	Domains:                       &DefaultDomains,
	DecapType:                     &DefaultDecapType,
	HTTPLogSpanID:                 &DefaultHTTPLogSpanID,
	SysFreeMemoryLimit:            &DefaultSysFreeMemoryLimit,
	LogFileSize:                   &DefaultLogFileSize,
	HTTPLogXRequestID:             &DefaultHTTPLogXRequestID,
	ExternalAgentHTTPProxyEnabled: &DefaultExternalAgentHTTPProxyEnabled,
	ExternalAgentHTTPProxyPort:    &DefaultExternalAgentHTTPProxyPort,
	PrometheusHttpAPIAddresses:    &DefaultPrometheusHttpAPIAddresses,
	AnalyzerPort:                  &DefaultAnalyzerPort,
	ProxyControllerPort:           &DefaultProxyControllerPort,
	ProxyControllerIP:             &DefaultProxyControllerIP,
	AnalyzerIP:                    &DefaultAnalyzerIP,
	WasmPlugins:                   &DefaultWasmPlugins,
	SoPlugins:                     &DefaultSoPlugins,

	SystemLoadCircuitBreakerThreshold: &DefaultSystemLoadCircuitBreakerThreshold,
	SystemLoadCircuitBreakerRecover:   &DefaultSystemLoadCircuitBreakerRecover,
	SystemLoadCircuitBreakerMetric:    &DefaultSystemLoadCircuitBreakerMetric,
}

var (
	DefaultMaxCollectPps                 = 200000
	DefaultMaxNpbBps                     = int64(1000000000)
	DefaultMaxCPUs                       = 1
	DefaultMaxMemory                     = 768
	DefaultPlatformSyncInterval          = 10
	DefaultSyncInterval                  = 60
	DefaultStatsInterval                 = 10
	DefaultRsyslogEnabled                = 1
	DefaultMaxTxBandwidth                = int64(0)
	DefaultBandwidthProbeInterval        = 10
	DefaultTapInterfaceRegex             = "^(tap.*|cali.*|veth.*|eth.*|en[osipx].*|lxc.*|lo|[0-9a-f]+_h)$"
	DefaultMaxEscapeSeconds              = 3600
	DefaultMtu                           = 1500
	DefaultOutputVlan                    = 0
	DefaultCollectorSocketType           = "TCP"
	DefaultCompressorSocketType          = "TCP"
	DefaultNpbSocketType                 = "RAW_UDP"
	DefaultNpbVlanMode                   = 0
	DefaultCollectorEnabled              = 1
	DefaultVTapFlow1sEnabled             = 1
	DefaultL4LogTapTypes                 = "0"
	DefaultL4LogIgnoreTapSides           = ""
	DefaultL7LogIgnoreTapSides           = ""
	DefaultNpbDedupEnabled               = 1
	DefaultPlatformEnabled               = 0
	DefaultIfMacSource                   = 0
	DefaultVMXMLPath                     = "/etc/libvirt/qemu/"
	DefaultExtraNetnsRegex               = ""
	DefaultNatIPEnabled                  = 0
	DefaultCapturePacketSize             = 65535
	DefaultInactiveServerPortEnabled     = 1
	DefaultInactiveIPEnabled             = 1
	DefaultLogThreshold                  = 300
	DefaultLogLevel                      = "INFO"
	DefaultLogRetention                  = 30
	DefaultHTTPLogProxyClient            = "X-Forwarded-For"
	DefaultHTTPLogTraceID                = "traceparent, sw8"
	DefaultL7LogPacketSize               = 1024
	DefaultL4LogCollectNpsThreshold      = 10000
	DefaultL7LogCollectNpsThreshold      = 10000
	DefaultL7MetricsEnabled              = 1
	DefaultL7LogStoreTapTypes            = "0"
	DefaultCaptureSocketType             = 0
	DefaultCaptureBpf                    = ""
	DefaultTapMode                       = TAPMODE_LOCAL
	DefaultThreadThreshold               = 500
	DefaultProcessThreshold              = 10
	DefaultNtpEnabled                    = 0
	DefaultL4PerformanceEnabled          = 1
	DefaultPodClusterInternalIP          = 0
	DefaultDomains                       = "0"
	DefaultDecapType                     = "1,2"
	DefaultHTTPLogSpanID                 = "traceparent, sw8"
	DefaultSysFreeMemoryLimit            = 0
	DefaultLogFileSize                   = 1000
	DefaultHTTPLogXRequestID             = "X-Request-ID"
	DefaultExternalAgentHTTPProxyEnabled = 1 // 外部Agent数据HTTP代理开关
	DefaultExternalAgentHTTPProxyPort    = 38086
	DefaultPrometheusHttpAPIAddresses    = ""
	DefaultAnalyzerPort                  = 30033
	DefaultProxyControllerPort           = 30035
	DefaultProxyControllerIP             = ""
	DefaultAnalyzerIP                    = ""
	DefaultWasmPlugins                   = ""
	DefaultSoPlugins                     = ""

	DefaultSystemLoadCircuitBreakerThreshold = float32(1.0)
	DefaultSystemLoadCircuitBreakerRecover   = float32(0.9)
	DefaultSystemLoadCircuitBreakerMetric    = "load15"
)
