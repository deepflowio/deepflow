/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

var DefaultVTapGroupConfig = &mysql.VTapGroupConfiguration{
	MaxCollectPps:                 &MaxCollectPps,
	MaxNpbBps:                     &MaxNpbBps,
	MaxCPUs:                       &MaxCPUs,
	MaxMemory:                     &MaxMemory,
	SyncInterval:                  &SyncInterval,
	StatsInterval:                 &StatsInterval,
	RsyslogEnabled:                &RsyslogEnabled,
	MaxTxBandwidth:                &MaxTxBandwidth,
	BandwidthProbeInterval:        &BandwidthProbeInterval,
	TapInterfaceRegex:             &TapInterfaceRegex,
	MaxEscapeSeconds:              &MaxEscapeSeconds,
	Mtu:                           &Mtu,
	OutputVlan:                    &OutputVlan,
	CollectorSocketType:           &CollectorSocketType,
	CompressorSocketType:          &CompressorSocketType,
	NpbSocketType:                 &NpbSocketType,
	NpbVlanMode:                   &NpbVlanMode,
	CollectorEnabled:              &CollectorEnabled,
	VTapFlow1sEnabled:             &VTapFlow1sEnabled,
	L4LogTapTypes:                 &L4LogTapTypes,
	NpbDedupEnabled:               &NpbDedupEnabled,
	PlatformEnabled:               &PlatformEnabled,
	IfMacSource:                   &IfMacSource,
	VMXMLPath:                     &VMXMLPath,
	NatIPEnabled:                  &NatIPEnabled,
	CapturePacketSize:             &CapturePacketSize,
	InactiveServerPortEnabled:     &InactiveServerPortEnabled,
	InactiveIPEnabled:             &InactiveIPEnabled,
	LogThreshold:                  &LogThreshold,
	LogLevel:                      &LogLevel,
	LogRetention:                  &LogRetention,
	HTTPLogProxyClient:            &HTTPLogProxyClient,
	HTTPLogTraceID:                &HTTPLogTraceID,
	L7LogPacketSize:               &L7LogPacketSize,
	L4LogCollectNpsThreshold:      &L4LogCollectNpsThreshold,
	L7LogCollectNpsThreshold:      &L7LogCollectNpsThreshold,
	L7MetricsEnabled:              &L7MetricsEnabled,
	L7LogStoreTapTypes:            &L7LogStoreTapTypes,
	CaptureSocketType:             &CaptureSocketType,
	CaptureBpf:                    &CaptureBpf,
	ThreadThreshold:               &ThreadThreshold,
	ProcessThreshold:              &ProcessThreshold,
	NtpEnabled:                    &NtpEnabled,
	L4PerformanceEnabled:          &L4PerformanceEnabled,
	PodClusterInternalIP:          &PodClusterInternalIP,
	Domains:                       &Domains,
	DecapType:                     &DecapType,
	HTTPLogSpanID:                 &HTTPLogSpanID,
	SysFreeMemoryLimit:            &SysFreeMemoryLimit,
	LogFileSize:                   &LogFileSize,
	HTTPLogXRequestID:             &HTTPLogXRequestID,
	ExternalAgentHTTPProxyEnabled: &ExternalAgentHTTPProxyEnabled,
	ExternalAgentHTTPProxyPort:    &ExternalAgentHTTPProxyPort,
	AnalyzerPort:                  &AnalyzerPort,
	ProxyControllerPort:           &ProxyControllerPort,
}

var (
	MaxCollectPps                 = 200000
	MaxNpbBps                     = int64(1000000000)
	MaxCPUs                       = 1
	MaxMemory                     = 768
	SyncInterval                  = 60
	StatsInterval                 = 60
	RsyslogEnabled                = 1
	MaxTxBandwidth                = int64(0)
	BandwidthProbeInterval        = 10
	TapInterfaceRegex             = "^(tap.*|cali.*|veth.*|eth.*|en[ospx].*|lxc.*|lo|[0-9a-f]+_h)$"
	MaxEscapeSeconds              = 3600
	Mtu                           = 1500
	OutputVlan                    = 0
	CollectorSocketType           = "TCP"
	CompressorSocketType          = "TCP"
	NpbSocketType                 = "RAW_UDP"
	NpbVlanMode                   = 0
	CollectorEnabled              = 1
	VTapFlow1sEnabled             = 1
	L4LogTapTypes                 = "0"
	NpbDedupEnabled               = 1
	PlatformEnabled               = 0
	IfMacSource                   = 0
	VMXMLPath                     = "/etc/libvirt/qemu/"
	ExtraNetnsRegex               = ""
	NatIPEnabled                  = 0
	CapturePacketSize             = 65535
	InactiveServerPortEnabled     = 1
	InactiveIPEnabled             = 1
	LogThreshold                  = 300
	LogLevel                      = "INFO"
	LogRetention                  = 30
	HTTPLogProxyClient            = "X-Forwarded-For"
	HTTPLogTraceID                = "traceparent, sw8"
	L7LogPacketSize               = 1024
	L4LogCollectNpsThreshold      = 10000
	L7LogCollectNpsThreshold      = 10000
	L7MetricsEnabled              = 1
	L7LogStoreTapTypes            = "0"
	CaptureSocketType             = 0
	CaptureBpf                    = ""
	ThreadThreshold               = 500
	ProcessThreshold              = 10
	NtpEnabled                    = 1
	L4PerformanceEnabled          = 1
	PodClusterInternalIP          = 0
	Domains                       = "0"
	DecapType                     = "1,2"
	HTTPLogSpanID                 = "traceparent, sw8"
	SysFreeMemoryLimit            = 0
	LogFileSize                   = 1000
	HTTPLogXRequestID             = "X-Request-ID"
	ExternalAgentHTTPProxyEnabled = 0
	ExternalAgentHTTPProxyPort    = 38086
	AnalyzerPort                  = 30033
	ProxyControllerPort           = 30035
)
