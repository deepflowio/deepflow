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

use std::cmp::{max, min};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, process};

use arc_swap::{access::Map, ArcSwap};
use bytesize::ByteSize;
use cgroups_rs::{CpuResources, MemoryResources, Resources};
use flexi_logger::writers::FileLogWriter;
use flexi_logger::{Age, Cleanup, Criterion, FileSpec, LoggerHandle, Naming};
use log::{info, warn, Level};

use super::config::PortConfig;
use super::{
    config::{Config, PcapConfig, YamlConfig},
    ConfigError, IngressFlavour, KubernetesPollerType, RuntimeConfig,
};

use crate::{
    common::{decapsulate::TunnelTypeBitmap, enums::TapType, DEFAULT_CPU_CFS_PERIOD_US},
    dispatcher::recv_engine::{self, OptTpacketVersion},
    ebpf::CAP_LEN_MAX,
    exception::ExceptionHandler,
    flow_generator::{FlowTimeout, TcpTimeout},
    integration_collector::check_listen_port_alive,
    proto::trident::{self, CaptureSocketType},
    proto::{
        common::TridentType,
        trident::{Exception, IfMacSource, SocketType, TapMode},
    },
    trident::Components,
    utils::cgroups::Cgroups,
    utils::environment::{free_memory_check, is_tt_pod, is_tt_workload},
    utils::logger::RemoteLogConfig,
    utils::net::{get_ctrl_ip_and_mac, MacAddr},
};

const MB: u64 = 1048576;
const MINUTE: Duration = Duration::from_secs(60);
const SECOND: Duration = Duration::from_secs(1);
const INFLUX_DB_PORT: u16 = 8086;

type Access<C> = Map<Arc<ArcSwap<ModuleConfig>>, ModuleConfig, fn(&ModuleConfig) -> &C>;

pub type CollectorAccess = Access<CollectorConfig>;

pub type EnvironmentAccess = Access<EnvironmentConfig>;

pub type SenderAccess = Access<SenderConfig>;

pub type PlatformAccess = Access<PlatformConfig>;

pub type HandlerAccess = Access<HandlerConfig>;

pub type DispatcherAccess = Access<DispatcherConfig>;

pub type DiagnoseAccess = Access<DiagnoseConfig>;

pub type LogAccess = Access<LogConfig>;

pub type FlowAccess = Access<FlowConfig>;

pub type LogParserAccess = Access<LogParserConfig>;

pub type PcapAccess = Access<PcapConfig>;

pub type DebugAccess = Access<DebugConfig>;

pub type SynchronizerAccess = Access<SynchronizerConfig>;

pub type EbpfAccess = Access<EbpfConfig>;

pub type MetricServerAccess = Access<MetricServerConfig>;

pub type PortAccess = Access<PortConfig>;

#[derive(Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    pub enabled: bool,
    pub inactive_server_port_enabled: bool,
    pub vtap_flow_1s_enabled: bool,
    pub l4_log_collect_nps_threshold: u64,
    pub l4_log_store_tap_types: [bool; 256],
    pub l7_metrics_enabled: bool,
    pub trident_type: TridentType,
    pub vtap_id: u16,
    pub cloud_gateway_traffic: bool,
}

impl fmt::Debug for CollectorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectorConfig")
            .field("enabled", &self.enabled)
            .field(
                "inactive_server_port_enabled",
                &self.inactive_server_port_enabled,
            )
            .field("vtap_flow_1s_enabled", &self.vtap_flow_1s_enabled)
            .field(
                "l4_log_store_tap_types",
                &self
                    .l4_log_store_tap_types
                    .iter()
                    .enumerate()
                    .filter(|&(_, b)| *b)
                    .collect::<Vec<_>>(),
            )
            .field(
                "l4_log_collect_nps_threshold",
                &self.l4_log_collect_nps_threshold,
            )
            .field("l7_metrics_enabled", &self.l7_metrics_enabled)
            .field("trident_type", &self.trident_type)
            .field("vtap_id", &self.vtap_id)
            .field("cloud_gateway_traffic", &self.cloud_gateway_traffic)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnvironmentConfig {
    pub max_memory: u64,
    pub max_cpus: u32,
    pub process_threshold: u32,
    pub thread_threshold: u32,
    pub sys_free_memory_limit: u32,
    pub log_file_size: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SenderConfig {
    pub mtu: u32,
    pub dest_ip: IpAddr,
    pub vtap_id: u16,
    pub dest_port: u16,
    pub npb_vlan_mode: trident::VlanMode,
    pub npb_dedup_enabled: bool,
    pub npb_bps_threshold: u64,
    pub npb_socket_type: trident::SocketType,
    pub compressor_socket_type: trident::SocketType,
    pub collector_socket_type: trident::SocketType,
    pub log_dir: String,
    pub server_tx_bandwidth_threshold: u64,
    pub bandwidth_probe_interval: Duration,
    pub enabled: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlatformConfig {
    pub sync_interval: Duration,
    pub kubernetes_cluster_id: String,
    pub libvirt_xml_path: PathBuf,
    pub kubernetes_poller_type: KubernetesPollerType,
    pub vtap_id: u16,
    pub enabled: bool,
    pub ingress_flavour: IngressFlavour,
    pub trident_type: TridentType,
    pub source_ip: IpAddr,
    pub epc_id: u32,
    pub kubernetes_api_enabled: bool,
    pub namespace: Option<String>,
}

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct HandlerConfig {
    pub compressor_socket_type: SocketType,
    pub npb_dedup_enabled: bool,
    pub trident_type: TridentType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DispatcherConfig {
    pub global_pps_threshold: u64,
    pub capture_packet_size: u32,
    pub l7_log_packet_size: u32,
    pub tunnel_type_bitmap: TunnelTypeBitmap,
    pub trident_type: TridentType,
    pub vtap_id: u16,
    pub capture_socket_type: CaptureSocketType,
    pub tap_interface_regex: String,
    pub packet_header_enabled: bool,
    pub if_mac_source: IfMacSource,
    pub analyzer_ip: IpAddr,
    pub analyzer_port: u16,
    pub proxy_controller_ip: IpAddr,
    pub proxy_controller_port: u16,
    pub capture_bpf: String,
    pub max_memory: u64,
    pub af_packet_blocks: usize,
    pub af_packet_version: OptTpacketVersion,
    pub tap_mode: TapMode,
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub enabled: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LogConfig {
    pub log_level: Level,
    pub log_threshold: u32,
    pub log_retention: u32,
    pub rsyslog_enabled: bool,
    pub host: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FlowConfig {
    pub vtap_id: u16,
    pub trident_type: TridentType,
    pub cloud_gateway_traffic: bool,
    pub collector_enabled: bool,
    pub l7_log_tap_types: [bool; 256],

    pub packet_delay: Duration,
    pub flush_interval: Duration,
    pub flow_timeout: FlowTimeout,
    pub ignore_tor_mac: bool,
    pub ignore_l2_end: bool,

    pub l7_metrics_enabled: bool,
    pub app_proto_log_enabled: bool,
    pub l4_performance_enabled: bool,
    pub l7_log_packet_size: u32,

    pub l7_protocol_inference_max_fail_count: usize,
    pub l7_protocol_inference_ttl: usize,

    // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_flag: u8,
    pub packet_sequence_block_size: usize,
}

impl From<&RuntimeConfig> for FlowConfig {
    fn from(conf: &RuntimeConfig) -> Self {
        let flow_config = &conf.yaml_config.flow;
        FlowConfig {
            vtap_id: conf.vtap_id as u16,
            trident_type: conf.trident_type,
            cloud_gateway_traffic: conf.yaml_config.cloud_gateway_traffic,
            collector_enabled: conf.collector_enabled,
            l7_log_tap_types: conf.l7_log_store_tap_types,
            packet_delay: conf.yaml_config.packet_delay,
            flush_interval: flow_config.flush_interval,
            flow_timeout: FlowTimeout::from(TcpTimeout {
                established: flow_config.established_timeout,
                closing_rst: flow_config.closing_rst_timeout,
                others: flow_config.others_timeout,
            }),
            ignore_tor_mac: flow_config.ignore_tor_mac,
            ignore_l2_end: flow_config.ignore_l2_end,
            l7_metrics_enabled: conf.l7_metrics_enabled,
            app_proto_log_enabled: conf.app_proto_log_enabled,
            l4_performance_enabled: conf.l4_performance_enabled,
            l7_log_packet_size: conf.l7_log_packet_size,
            l7_protocol_inference_max_fail_count: conf
                .yaml_config
                .l7_protocol_inference_max_fail_count,
            l7_protocol_inference_ttl: conf.yaml_config.l7_protocol_inference_ttl,
            packet_sequence_flag: conf.yaml_config.packet_sequence_flag, // Enterprise Edition Feature: packet-sequence
            packet_sequence_block_size: conf.yaml_config.packet_sequence_block_size, // Enterprise Edition Feature: packet-sequence
        }
    }
}

impl fmt::Debug for FlowConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowConfig")
            .field("vtap_id", &self.vtap_id)
            .field("trident_type", &self.trident_type)
            .field("collector_enabled", &self.collector_enabled)
            .field(
                "l7_log_tap_types",
                &self
                    .l7_log_tap_types
                    .iter()
                    .enumerate()
                    .filter(|&(_, b)| *b)
                    .collect::<Vec<_>>(),
            )
            .field("packet_delay", &self.packet_delay)
            .field("flush_interval", &self.flush_interval)
            .field("flow_timeout", &self.flow_timeout)
            .field("ignore_tor_mac", &self.ignore_tor_mac)
            .field("ignore_l2_end", &self.ignore_l2_end)
            .field("l7_metrics_enabled", &self.l7_metrics_enabled)
            .field("app_proto_log_enabled", &self.app_proto_log_enabled)
            .field("l4_performance_enabled", &self.l4_performance_enabled)
            .field("l7_log_packet_size", &self.l7_log_packet_size)
            .field(
                "l7_protocol_inference_max_fail_count",
                &self.l7_protocol_inference_max_fail_count,
            )
            .field("l7_protocol_inference_ttl", &self.l7_protocol_inference_ttl)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LogParserConfig {
    pub l7_log_collect_nps_threshold: u64,
    pub l7_log_session_aggr_timeout: Duration,
    pub l7_log_dynamic: L7LogDynamicConfig,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DebugConfig {
    pub vtap_id: u16,
    pub enabled: bool,
    pub controller_ips: Vec<IpAddr>,
    pub listen_port: u16,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DiagnoseConfig {
    pub enabled: bool,
    pub libvirt_xml_path: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StatsConfig {
    pub interval: Duration,
    pub host: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SynchronizerConfig {
    pub sync_interval: Duration,
    pub ntp_enabled: bool,
    pub max_escape: Duration,
    pub output_vlan: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EbpfConfig {
    // 动态配置
    pub collector_enabled: bool,
    pub l7_metrics_enabled: bool,
    pub vtap_id: u16,
    pub epc_id: u32,
    pub l7_log_packet_size: usize,
    // 静态配置
    pub l7_log_session_timeout: Duration,
    pub l7_protocol_inference_max_fail_count: usize,
    pub l7_protocol_inference_ttl: usize,
    pub log_path: String,
    pub l7_log_tap_types: [bool; 256],
    pub ctrl_mac: MacAddr,
}

impl fmt::Debug for EbpfConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EbpfConfig")
            .field("collector_enabled", &self.collector_enabled)
            .field("l7_metrics_enabled", &self.l7_metrics_enabled)
            .field("vtap_id", &self.vtap_id)
            .field("epc_id", &self.epc_id)
            .field("l7_log_packet_size", &self.l7_log_packet_size)
            .field("l7_log_session_timeout", &self.l7_log_session_timeout)
            .field(
                "l7_protocol_inference_max_fail_count",
                &self.l7_protocol_inference_max_fail_count,
            )
            .field("l7_protocol_inference_ttl", &self.l7_protocol_inference_ttl)
            .field("log_path", &self.log_path)
            .field(
                "l7_log_tap_types",
                &self
                    .l7_log_tap_types
                    .iter()
                    .enumerate()
                    .filter(|&(_, b)| *b)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EbpfConfig {
    pub fn l7_log_enabled(&self) -> bool {
        // Afpacket应用日志依赖l7_metrics_enabled和collector_enabled，这里统一逻辑
        if !self.l7_metrics_enabled || !self.collector_enabled {
            return false;
        }
        // Ebpf应用日志都是虚拟的，这里仅需要判断ANY和TOR
        return self.l7_log_tap_types[u16::from(TapType::Any) as usize]
            || self.l7_log_tap_types[u16::from(TapType::Tor) as usize];
    }
}

// Span/Trace 共用一套TypeMap
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TraceType {
    Disabled, // 业务表示关闭
    XB3,
    XB3Span,
    Uber,
    Sw6,
    Sw8,
    TraceParent,
    Customize(String),
}

const TRACE_TYPE_XB3: &str = "X-B3-TraceId";
const TRACE_TYPE_XB3SPAN: &str = "X-B3-SpanId";
const TRACE_TYPE_UBER: &str = "uber-trace-id";
const TRACE_TYPE_SW6: &str = "sw6";
const TRACE_TYPE_SW8: &str = "sw8";
const TRACE_TYPE_TRACE_PARENT: &str = "traceparent";

impl From<&str> for TraceType {
    // 参数支持如下两种格式：
    // 示例1：" sw8"
    // 示例2："sw8"
    // ==================================================
    // The parameter supports the following two formats:
    // Example 1: "sw8"
    // Example 2: " sw8"
    fn from(t: &str) -> TraceType {
        let t = Self::format_str(t);
        match t {
            TRACE_TYPE_XB3 => TraceType::XB3,
            TRACE_TYPE_XB3SPAN => TraceType::XB3Span,
            TRACE_TYPE_UBER => TraceType::Uber,
            TRACE_TYPE_SW6 => TraceType::Sw6,
            TRACE_TYPE_SW8 => TraceType::Sw8,
            TRACE_TYPE_TRACE_PARENT => TraceType::TraceParent,
            _ if t.len() > 0 => TraceType::Customize(t.to_string()),
            _ => TraceType::Disabled,
        }
    }
}

impl TraceType {
    // 删除有效位前的所有空格
    // ============================================
    // Remove all spaces before significant digits
    fn format_str(t: &str) -> &str {
        let bytes = t.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] != b' ' as u8 {
                return &t[i..];
            }
        }
        return t;
    }

    fn check(&self, context: &str) -> bool {
        match &*self {
            TraceType::XB3 => context.to_lowercase() == TRACE_TYPE_XB3.to_lowercase(),
            TraceType::XB3Span => context.to_lowercase() == TRACE_TYPE_XB3SPAN.to_lowercase(),
            TraceType::Uber => context == TRACE_TYPE_UBER,
            TraceType::Sw6 => context == TRACE_TYPE_SW6,
            TraceType::Sw8 => context == TRACE_TYPE_SW8,
            TraceType::TraceParent => context == TRACE_TYPE_TRACE_PARENT,
            TraceType::Customize(tag) => context == tag.as_str(),
            _ => false,
        }
    }

    pub fn to_string(&self) -> String {
        match &*self {
            TraceType::XB3 => TRACE_TYPE_XB3.to_string(),
            TraceType::XB3Span => TRACE_TYPE_XB3SPAN.to_string(),
            TraceType::Uber => TRACE_TYPE_UBER.to_string(),
            TraceType::Sw6 => TRACE_TYPE_SW6.to_string(),
            TraceType::Sw8 => TRACE_TYPE_SW8.to_string(),
            TraceType::TraceParent => TRACE_TYPE_TRACE_PARENT.to_string(),
            TraceType::Customize(tag) => tag.to_string(),
            _ => "".to_string(),
        }
    }
}

impl Default for TraceType {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct L7LogDynamicConfig {
    pub proxy_client_origin: String,
    pub proxy_client_lower: String,
    pub proxy_client_with_colon: String,
    pub x_request_id_origin: String,
    pub x_request_id_lower: String,
    pub x_request_id_with_colon: String,

    pub trace_types: Vec<TraceType>,
    pub span_types: Vec<TraceType>,
}

impl L7LogDynamicConfig {
    pub fn is_trace_id(&self, context: &str) -> bool {
        for trace in &self.trace_types {
            if trace.check(context) {
                return true;
            }
        }
        return false;
    }

    pub fn is_span_id(&self, context: &str) -> bool {
        for span in &self.span_types {
            if span.check(context) {
                return true;
            }
        }
        return false;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricServerConfig {
    pub enabled: bool,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub yaml_config: YamlConfig,
    pub collector: CollectorConfig,
    pub environment: EnvironmentConfig,
    pub platform: PlatformConfig,
    pub dispatcher: DispatcherConfig,
    pub flow: FlowConfig,
    pub log_parser: LogParserConfig,
    pub pcap: PcapConfig,
    pub debug: DebugConfig,
    pub diagnose: DiagnoseConfig,
    pub stats: StatsConfig,
    pub sender: SenderConfig,
    pub handler: HandlerConfig,
    pub log: LogConfig,
    pub synchronizer: SynchronizerConfig,
    pub ebpf: EbpfConfig,
    pub trident_type: TridentType,
    pub metric_server: MetricServerConfig,
    pub port_config: PortConfig,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self::try_from((
            Config {
                controller_ips: vec!["127.0.0.1".into()],
                ..Default::default()
            },
            RuntimeConfig::default(),
        ))
        .unwrap()
    }
}

impl TryFrom<(Config, RuntimeConfig)> for ModuleConfig {
    type Error = ConfigError;

    fn try_from(conf: (Config, RuntimeConfig)) -> Result<Self, Self::Error> {
        let (static_config, conf) = conf;
        let (ctrl_ip, ctrl_mac) =
            get_ctrl_ip_and_mac(static_config.controller_ips[0].parse().unwrap());
        let dest_ip = conf
            .analyzer_ip
            .parse::<IpAddr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED.into());
        let proxy_controller_ip = conf
            .proxy_controller_ip
            .parse()
            .unwrap_or(static_config.controller_ips[0].parse::<IpAddr>().unwrap());

        let config = ModuleConfig {
            enabled: conf.enabled,
            yaml_config: conf.yaml_config.clone(),
            diagnose: DiagnoseConfig {
                enabled: conf.enabled,
                libvirt_xml_path: conf.libvirt_xml_path.parse().unwrap_or_default(),
            },
            environment: EnvironmentConfig {
                max_memory: conf.max_memory,
                max_cpus: conf.max_cpus,
                process_threshold: conf.process_threshold,
                thread_threshold: conf.thread_threshold,
                sys_free_memory_limit: conf.sys_free_memory_limit,
                log_file_size: conf.log_file_size,
            },
            synchronizer: SynchronizerConfig {
                sync_interval: conf.sync_interval,
                output_vlan: conf.output_vlan,
                ntp_enabled: conf.ntp_enabled,
                max_escape: conf.max_escape,
            },
            stats: StatsConfig {
                interval: conf.stats_interval,
                host: conf.host.clone(),
            },
            dispatcher: DispatcherConfig {
                global_pps_threshold: conf.global_pps_threshold,
                capture_packet_size: conf.capture_packet_size,
                l7_log_packet_size: conf.l7_log_packet_size,
                tunnel_type_bitmap: TunnelTypeBitmap::new(&conf.decap_types),
                trident_type: conf.trident_type,
                vtap_id: conf.vtap_id as u16,
                capture_socket_type: conf.capture_socket_type,
                tap_interface_regex: conf.tap_interface_regex.to_string(),
                packet_header_enabled: conf.packet_header_enabled,
                if_mac_source: conf.if_mac_source,
                analyzer_ip: dest_ip,
                analyzer_port: conf.analyzer_port,
                proxy_controller_ip,
                proxy_controller_port: conf.proxy_controller_port,
                capture_bpf: conf.capture_bpf.to_string(),
                max_memory: conf.max_memory,
                af_packet_blocks: conf.yaml_config.get_af_packet_blocks(conf.max_memory),
                af_packet_version: conf.capture_socket_type.into(),
                tap_mode: conf.yaml_config.tap_mode,
                region_id: conf.region_id,
                pod_cluster_id: conf.pod_cluster_id,
                enabled: conf.enabled,
            },
            sender: SenderConfig {
                mtu: conf.mtu,
                dest_ip,
                vtap_id: conf.vtap_id as u16,
                dest_port: conf.analyzer_port,
                npb_vlan_mode: conf.npb_vlan_mode,
                npb_dedup_enabled: conf.npb_dedup_enabled,
                npb_bps_threshold: conf.npb_bps_threshold,
                npb_socket_type: conf.npb_socket_type,
                compressor_socket_type: conf.compressor_socket_type,
                server_tx_bandwidth_threshold: conf.server_tx_bandwidth_threshold,
                bandwidth_probe_interval: conf.bandwidth_probe_interval,
                collector_socket_type: conf.collector_socket_type,
                log_dir: Path::new(&static_config.log_file)
                    .parent()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
                enabled: conf.collector_enabled,
            },
            collector: CollectorConfig {
                enabled: conf.collector_enabled,
                inactive_server_port_enabled: conf.inactive_server_port_enabled,
                vtap_flow_1s_enabled: conf.vtap_flow_1s_enabled,
                l4_log_collect_nps_threshold: conf.l4_log_collect_nps_threshold,
                l7_metrics_enabled: conf.l7_metrics_enabled,
                trident_type: conf.trident_type,
                vtap_id: conf.vtap_id as u16,
                l4_log_store_tap_types: conf.l4_log_store_tap_types,
                cloud_gateway_traffic: conf.yaml_config.cloud_gateway_traffic,
            },
            handler: HandlerConfig {
                compressor_socket_type: conf.compressor_socket_type,
                npb_dedup_enabled: conf.npb_dedup_enabled,
                trident_type: conf.trident_type,
            },
            pcap: conf.yaml_config.pcap.clone(),
            platform: PlatformConfig {
                sync_interval: MINUTE,
                kubernetes_cluster_id: static_config.kubernetes_cluster_id.clone(),
                libvirt_xml_path: conf.libvirt_xml_path.parse().unwrap_or_default(),
                kubernetes_poller_type: conf.yaml_config.kubernetes_poller_type,
                vtap_id: conf.vtap_id as u16,
                enabled: conf.platform_enabled,
                ingress_flavour: conf.yaml_config.ingress_flavour,
                trident_type: conf.trident_type,
                source_ip: ctrl_ip,
                epc_id: conf.epc_id,
                kubernetes_api_enabled: conf.kubernetes_api_enabled,
                namespace: if conf.yaml_config.kubernetes_namespace.is_empty() {
                    None
                } else {
                    Some(conf.yaml_config.kubernetes_namespace.clone())
                },
            },
            flow: (&conf).into(),
            log_parser: LogParserConfig {
                l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold,
                l7_log_session_aggr_timeout: conf.yaml_config.l7_log_session_aggr_timeout,
                l7_log_dynamic: L7LogDynamicConfig {
                    proxy_client_origin: conf.http_log_proxy_client.to_string(),
                    proxy_client_lower: conf.http_log_proxy_client.to_string().to_lowercase(),
                    proxy_client_with_colon: format!("{}: ", conf.http_log_proxy_client),

                    x_request_id_origin: conf.http_log_x_request_id.to_string(),
                    x_request_id_lower: conf.http_log_x_request_id.to_string().to_lowercase(),
                    x_request_id_with_colon: format!("{}: ", conf.http_log_x_request_id),

                    trace_types: conf
                        .http_log_trace_id
                        .split(',')
                        .map(|item| TraceType::from(item))
                        .collect(),
                    span_types: conf
                        .http_log_span_id
                        .split(',')
                        .map(|item| TraceType::from(item))
                        .collect(),
                },
            },
            debug: DebugConfig {
                vtap_id: conf.vtap_id as u16,
                enabled: conf.debug_enabled,
                controller_ips: static_config
                    .controller_ips
                    .iter()
                    .map(|c| c.parse::<IpAddr>().unwrap())
                    .collect(),
                listen_port: conf.yaml_config.debug_listen_port,
            },
            log: LogConfig {
                log_level: conf.log_level,
                log_threshold: conf.log_threshold,
                log_retention: conf.log_retention,
                rsyslog_enabled: conf.rsyslog_enabled,
                host: conf.host.clone(),
            },
            ebpf: EbpfConfig {
                collector_enabled: conf.collector_enabled,
                l7_metrics_enabled: conf.l7_metrics_enabled,
                vtap_id: conf.vtap_id as u16,
                epc_id: conf.epc_id,
                l7_log_session_timeout: conf.yaml_config.l7_log_session_aggr_timeout,
                log_path: conf.yaml_config.ebpf_log_file.clone(),
                l7_log_packet_size: CAP_LEN_MAX.min(conf.l7_log_packet_size as usize),
                l7_log_tap_types: conf.l7_log_store_tap_types,
                l7_protocol_inference_max_fail_count: conf
                    .yaml_config
                    .l7_protocol_inference_max_fail_count,
                l7_protocol_inference_ttl: conf.yaml_config.l7_protocol_inference_ttl,
                ctrl_mac: if is_tt_workload(conf.trident_type) {
                    ctrl_mac
                } else {
                    MacAddr::ZERO
                },
            },
            metric_server: MetricServerConfig {
                enabled: conf.external_agent_http_proxy_enabled,
                port: conf.external_agent_http_proxy_port as u16,
            },
            trident_type: conf.trident_type,
            port_config: PortConfig {
                analyzer_port: conf.analyzer_port,
                proxy_controller_port: conf.proxy_controller_port,
            },
        };
        Ok(config)
    }
}

pub struct ConfigHandler {
    pub ctrl_ip: IpAddr,
    pub ctrl_mac: MacAddr,
    pub logger_handle: LoggerHandle,
    pub remote_log_config: RemoteLogConfig,
    // need update
    pub static_config: Config,
    pub candidate_config: ModuleConfig,
    pub current_config: Arc<ArcSwap<ModuleConfig>>,
}

impl ConfigHandler {
    pub fn new(
        config: Config,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        logger_handle: LoggerHandle,
        remote_log_config: RemoteLogConfig,
    ) -> Self {
        let candidate_config =
            ModuleConfig::try_from((config.clone(), RuntimeConfig::default())).unwrap();
        let current_config = Arc::new(ArcSwap::from_pointee(candidate_config.clone()));

        Self {
            static_config: config,
            ctrl_ip,
            ctrl_mac,
            candidate_config,
            current_config,
            logger_handle,
            remote_log_config,
        }
    }

    pub fn collector(&self) -> CollectorAccess {
        Map::new(self.current_config.clone(), |config| -> &CollectorConfig {
            &config.collector
        })
    }

    pub fn environment(&self) -> EnvironmentAccess {
        Map::new(
            self.current_config.clone(),
            |config| -> &EnvironmentConfig { &config.environment },
        )
    }

    pub fn handler(&self) -> HandlerAccess {
        Map::new(self.current_config.clone(), |config| -> &HandlerConfig {
            &config.handler
        })
    }

    pub fn sender(&self) -> SenderAccess {
        Map::new(self.current_config.clone(), |config| -> &SenderConfig {
            &config.sender
        })
    }

    pub fn platform(&self) -> PlatformAccess {
        Map::new(self.current_config.clone(), |config| -> &PlatformConfig {
            &config.platform
        })
    }

    pub fn dispatcher(&self) -> DispatcherAccess {
        Map::new(self.current_config.clone(), |config| -> &DispatcherConfig {
            &config.dispatcher
        })
    }

    pub fn diagnose(&self) -> DiagnoseAccess {
        Map::new(self.current_config.clone(), |config| -> &DiagnoseConfig {
            &config.diagnose
        })
    }

    pub fn log(&self) -> LogAccess {
        Map::new(self.current_config.clone(), |config| -> &LogConfig {
            &config.log
        })
    }

    pub fn flow(&self) -> FlowAccess {
        Map::new(self.current_config.clone(), |config| -> &FlowConfig {
            &config.flow
        })
    }

    pub fn log_parser(&self) -> LogParserAccess {
        Map::new(self.current_config.clone(), |config| -> &LogParserConfig {
            &config.log_parser
        })
    }

    pub fn pcap(&self) -> PcapAccess {
        Map::new(self.current_config.clone(), |config| -> &PcapConfig {
            &config.pcap
        })
    }

    pub fn debug(&self) -> DebugAccess {
        Map::new(self.current_config.clone(), |config| -> &DebugConfig {
            &config.debug
        })
    }

    pub fn synchronizer(&self) -> SynchronizerAccess {
        Map::new(
            self.current_config.clone(),
            |config| -> &SynchronizerConfig { &config.synchronizer },
        )
    }

    pub fn ebpf(&self) -> EbpfAccess {
        Map::new(self.current_config.clone(), |config| -> &EbpfConfig {
            &config.ebpf
        })
    }

    pub fn metric_server(&self) -> MetricServerAccess {
        Map::new(
            self.current_config.clone(),
            |config| -> &MetricServerConfig { &config.metric_server },
        )
    }

    pub fn port(&self) -> PortAccess {
        Map::new(self.current_config.clone(), |config| -> &PortConfig {
            &config.port_config
        })
    }

    pub fn on_config(
        &mut self,
        new_config: RuntimeConfig,
        exception_handler: &ExceptionHandler,
    ) -> Vec<fn(&ConfigHandler, &mut Components)> {
        let candidate_config = &mut self.candidate_config;
        let static_config = &mut self.static_config;
        let yaml_config = &candidate_config.yaml_config;
        let mut new_config: ModuleConfig = (static_config.clone(), new_config).try_into().unwrap();
        let mut callbacks: Vec<fn(&ConfigHandler, &mut Components)> = vec![];
        //TODO dispatcher on_config_change 要迁移过来
        let mut restart_dispatcher = false;

        // Check and send out exceptions in time
        if let Err(e) = free_memory_check(new_config.environment.max_memory, exception_handler) {
            warn!("{}", e);
        }

        if candidate_config.dispatcher != new_config.dispatcher {
            if candidate_config.dispatcher.if_mac_source != new_config.dispatcher.if_mac_source {
                if yaml_config.tap_mode != TapMode::Local {
                    info!(
                        "if_mac_source set to {:?}",
                        new_config.dispatcher.if_mac_source
                    );
                }
            }

            if candidate_config.dispatcher.capture_packet_size
                != new_config.dispatcher.capture_packet_size
            {
                if yaml_config.tap_mode == TapMode::Analyzer || cfg!(target_os = "windows") {
                    todo!()
                }
            }

            if candidate_config.dispatcher.capture_socket_type
                != new_config.dispatcher.capture_socket_type
            {
                restart_dispatcher = !cfg!(target_os = "windows");
            }

            if candidate_config.dispatcher.enabled != new_config.dispatcher.enabled {
                info!("enabled set to {}", new_config.dispatcher.enabled);
                if new_config.dispatcher.enabled {
                    fn start_dispatcher(handler: &ConfigHandler, components: &mut Components) {
                        match free_memory_check(
                            handler.candidate_config.environment.max_memory,
                            &components.exception_handler,
                        ) {
                            Ok(()) => {
                                for dispatcher in components.dispatchers.iter() {
                                    dispatcher.start();
                                }
                            }
                            Err(e) => {
                                warn!("{}", e);
                            }
                        }
                    }
                    callbacks.push(start_dispatcher);
                } else {
                    fn stop_dispatcher(_: &ConfigHandler, components: &mut Components) {
                        for dispatcher in components.dispatchers.iter() {
                            dispatcher.stop();
                        }
                    }
                    callbacks.push(stop_dispatcher);
                }
            }

            if candidate_config.dispatcher.max_memory != new_config.dispatcher.max_memory {
                if yaml_config.get_af_packet_blocks(new_config.dispatcher.max_memory)
                    != yaml_config.get_af_packet_blocks(candidate_config.dispatcher.max_memory)
                    || yaml_config.get_fast_path_map_size(new_config.dispatcher.max_memory)
                        != yaml_config
                            .get_fast_path_map_size(candidate_config.dispatcher.max_memory)
                    || yaml_config.get_channel_size(new_config.dispatcher.max_memory)
                        != yaml_config.get_channel_size(candidate_config.dispatcher.max_memory)
                    || yaml_config.get_flow_capacity(new_config.dispatcher.max_memory)
                        != yaml_config.get_flow_capacity(candidate_config.dispatcher.max_memory)
                {
                    restart_dispatcher = true;
                    info!("max_memory change, restart dispatcher");
                }
            }

            if candidate_config.dispatcher.global_pps_threshold
                != new_config.dispatcher.global_pps_threshold
            {
                candidate_config.dispatcher.global_pps_threshold =
                    new_config.dispatcher.global_pps_threshold;

                fn leaky_bucket_callback(handler: &ConfigHandler, components: &mut Components) {
                    match handler.candidate_config.yaml_config.tap_mode {
                        TapMode::Analyzer => {
                            components.rx_leaky_bucket.set_rate(None);
                            info!("dispatcher.global pps set ulimit when tap_mode=analyzer");
                        }
                        _ => {
                            components.rx_leaky_bucket.set_rate(Some(
                                handler.candidate_config.dispatcher.global_pps_threshold,
                            ));
                            info!(
                                "dispatcher.global pps threshold change to {}",
                                handler.candidate_config.dispatcher.global_pps_threshold
                            );
                        }
                    }
                }
                callbacks.push(leaky_bucket_callback);
            }

            info!(
                "dispatcher config change from {:#?} to {:#?}",
                candidate_config.dispatcher, new_config.dispatcher
            );
            candidate_config.dispatcher = new_config.dispatcher;
        }

        if candidate_config.log != new_config.log {
            if new_config.log.host == "" {
                new_config.log.host = candidate_config.log.host.clone();
            }
            if candidate_config.log.rsyslog_enabled != new_config.log.rsyslog_enabled {
                if new_config.log.rsyslog_enabled {
                    info!("Enable rsyslog");
                } else {
                    info!("Disable rsyslog");
                }
                self.remote_log_config
                    .set_enabled(new_config.log.rsyslog_enabled);
            }
            if candidate_config.log.log_level != new_config.log.log_level {
                match self
                    .logger_handle
                    .parse_and_push_temp_spec(new_config.log.log_level.as_str().to_lowercase())
                {
                    Ok(_) => {
                        candidate_config.log.log_level = new_config.log.log_level;
                        info!("log level set to {}", new_config.log.log_level);
                    }
                    Err(e) => warn!("failed to set log_level: {}", e),
                }
            }
            if candidate_config.log.host != new_config.log.host {
                self.remote_log_config
                    .set_hostname(new_config.log.host.clone());
            }
            if candidate_config.log.log_threshold != new_config.log.log_threshold {
                info!("LogThreshold set to {}", new_config.log.log_threshold);
                self.remote_log_config
                    .set_threshold(new_config.log.log_threshold);
            }
            if candidate_config.log.log_retention != new_config.log.log_retention {
                match self.logger_handle.reset_flw(
                    &FileLogWriter::builder(FileSpec::try_from(&static_config.log_file).unwrap())
                        .rotate(
                            Criterion::Age(Age::Day),
                            Naming::Timestamps,
                            Cleanup::KeepLogFiles(new_config.log.log_retention as usize),
                        )
                        .create_symlink(&static_config.log_file)
                        .append(),
                ) {
                    Ok(_) => {
                        info!("log_retention set to {}", new_config.log.log_retention);
                    }
                    Err(e) => {
                        warn!("failed to set log_retention: {}", e);
                    }
                }
            }
            candidate_config.log = new_config.log;
        }

        if candidate_config.stats != new_config.stats {
            info!(
                "stats config change from {:#?} to {:#?}",
                candidate_config.stats, new_config.stats
            );
            fn stats_callback(handler: &ConfigHandler, components: &mut Components) {
                let c = &components.stats_collector;
                c.set_hostname(handler.candidate_config.stats.host.clone());
                c.set_min_interval(handler.candidate_config.stats.interval);
            }
            callbacks.push(stats_callback);
        }

        if candidate_config.debug != new_config.debug {
            info!(
                "debug config change from {:#?} to {:#?}",
                candidate_config.debug, new_config.debug
            );
            candidate_config.debug = new_config.debug;

            fn debug_callback(handler: &ConfigHandler, components: &mut Components) {
                if handler.candidate_config.debug.enabled {
                    components.debugger.start();
                } else {
                    components.debugger.stop();
                }
            }

            callbacks.push(debug_callback);
        }

        if candidate_config.diagnose != new_config.diagnose {
            //TODO diagnose stuff
            info!(
                "diagnose config change from {:#?} to {:#?}",
                candidate_config.diagnose, new_config.diagnose
            );
            candidate_config.diagnose = new_config.diagnose;
        }

        if candidate_config.environment != new_config.environment {
            let mut max_memory_change = false;
            let mut max_cpus_change = false;
            if candidate_config.environment.max_memory != new_config.environment.max_memory {
                max_memory_change = true;
                if yaml_config.tap_mode != TapMode::Analyzer {
                    // TODO policy.SetMemoryLimit(cfg.MaxMemory)
                    info!(
                        "memory limit set to {}",
                        ByteSize::b(new_config.environment.max_memory).to_string_as(true)
                    );
                    candidate_config.environment.max_memory = new_config.environment.max_memory;
                } else {
                    info!("memory set ulimit when tap_mode=analyzer");
                    candidate_config.environment.max_memory = 0;
                }
            }
            if candidate_config.environment.max_cpus != new_config.environment.max_cpus {
                max_cpus_change = true;
            }
            if max_memory_change || max_cpus_change {
                if static_config.kubernetes_cluster_id.is_empty() {
                    // 非容器类型采集器才做资源限制
                    fn cgroup_callback(handler: &ConfigHandler, components: &mut Components) {
                        if components.cgroups_controller.cgroup.is_none() {
                            match Cgroups::new() {
                                Ok(cc) => {
                                    if let Some(_) = &cc.cgroup {
                                        match cc.init(process::id() as u64) {
                                            Ok(cgroup) => {
                                                components.cgroups_controller = Arc::new(cgroup);
                                            }
                                            Err(e) => {
                                                warn!("{}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("{:?}", e);
                                }
                            };
                        }

                        let mut resources = Resources {
                            memory: Default::default(),
                            pid: Default::default(),
                            cpu: Default::default(),
                            devices: Default::default(),
                            network: Default::default(),
                            hugepages: Default::default(),
                            blkio: Default::default(),
                        };
                        if handler.candidate_config.environment.max_memory != 0 {
                            let memory_resources = MemoryResources {
                                kernel_memory_limit: None,
                                memory_hard_limit: Some(
                                    handler.candidate_config.environment.max_memory as i64,
                                ),
                                memory_soft_limit: None,
                                kernel_tcp_memory_limit: None,
                                memory_swap_limit: None,
                                swappiness: None,
                                attrs: Default::default(),
                            };
                            resources.memory = memory_resources.clone();
                        }
                        if handler.candidate_config.environment.max_cpus != 0 {
                            let cpu_quota = handler.candidate_config.environment.max_cpus
                                * DEFAULT_CPU_CFS_PERIOD_US;
                            let cpu_resources = CpuResources {
                                cpus: None,
                                mems: None,
                                shares: None,
                                quota: Some(cpu_quota as i64),
                                period: Some(DEFAULT_CPU_CFS_PERIOD_US as u64),
                                realtime_runtime: None,
                                realtime_period: None,
                                attrs: Default::default(),
                            };
                            resources.cpu = cpu_resources.clone();
                        }
                        match components.cgroups_controller.apply(&resources) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("set cgroups failed: {}", e);
                            }
                        }
                    }
                    callbacks.push(cgroup_callback);
                }
            }
            if candidate_config.environment.sys_free_memory_limit
                != new_config.environment.sys_free_memory_limit
            {
                info!(
                    "sys_free_memory_limit set to {}",
                    new_config.environment.sys_free_memory_limit
                );
                candidate_config.environment.sys_free_memory_limit =
                    new_config.environment.sys_free_memory_limit;
            }
            info!(
                "environment config change from {:#?} to {:#?}",
                candidate_config.environment, new_config.environment
            );

            candidate_config.environment = new_config.environment;
        }

        if cfg!(target_os = "windows") && yaml_config.tap_mode != TapMode::Analyzer {
            todo!();
        }

        if candidate_config.flow != new_config.flow {
            if candidate_config.flow.collector_enabled != new_config.flow.collector_enabled {
                restart_dispatcher = true;
            }
            info!(
                "flow_generator config change from {:#?} to {:#?}",
                candidate_config.flow, new_config.flow
            );
            candidate_config.flow = new_config.flow;
        }

        if candidate_config.collector != new_config.collector {
            if candidate_config.collector.l4_log_store_tap_types
                != new_config.collector.l4_log_store_tap_types
            {
                info!(
                    "collector config l4_log_store_tap_types change from {:?} to {:?}, will restart dispatcher",
                    candidate_config.collector.l4_log_store_tap_types
                                        .iter()
                                        .enumerate()
                                        .filter(|&(_, b)| *b)
                                        .collect::<Vec<_>>(),
                    new_config.collector.l4_log_store_tap_types
                                        .iter()
                                        .enumerate()
                                        .filter(|&(_, b)| *b)
                                        .collect::<Vec<_>>()
                );
                restart_dispatcher = true;
            }

            if candidate_config.collector.vtap_id != new_config.collector.vtap_id {
                if new_config.collector.enabled {
                    restart_dispatcher = true;
                }
            }

            fn quadruple_generator_callback(_: &ConfigHandler, components: &mut Components) {
                for collector in components.collectors.iter().as_ref() {
                    collector.quadruple_generator.update_config();
                }
            }
            callbacks.push(quadruple_generator_callback);

            info!(
                "collector config change from {:#?} to {:#?}",
                candidate_config.collector, new_config.collector
            );
            candidate_config.collector = new_config.collector;
        }

        if candidate_config.platform != new_config.platform {
            if candidate_config.platform.enabled != new_config.platform.enabled {
                info!("Platform enabled set to {}", new_config.platform.enabled);
            }
            if candidate_config.platform.kubernetes_api_enabled
                != new_config.platform.kubernetes_api_enabled
            {
                info!(
                    "Kubernetes API enabled set to {}",
                    new_config.platform.kubernetes_api_enabled
                );
            }
            info!(
                "platform config change from {:#?} to {:#?}",
                candidate_config.platform, new_config.platform
            );
            candidate_config.platform = new_config.platform;
            fn platform_callback(handler: &ConfigHandler, components: &mut Components) {
                if is_tt_pod(handler.candidate_config.platform.trident_type) {
                    components.platform_synchronizer.start_kubernetes_poller();
                } else {
                    components.platform_synchronizer.stop_kubernetes_poller();
                }
                if handler.candidate_config.platform.kubernetes_api_enabled {
                    components.api_watcher.start();
                } else {
                    components.api_watcher.stop();
                }
            }
            callbacks.push(platform_callback);
        }

        if candidate_config.sender != new_config.sender {
            if candidate_config.sender.collector_socket_type
                != new_config.sender.collector_socket_type
            {
                if candidate_config.sender.enabled != new_config.sender.enabled {
                    restart_dispatcher = true;
                }
            }
            if candidate_config.sender.compressor_socket_type
                != new_config.sender.compressor_socket_type
            {
                if candidate_config.dispatcher.packet_header_enabled {
                    restart_dispatcher = true;
                }
            }

            if candidate_config.sender.npb_socket_type != new_config.sender.npb_socket_type {
                if yaml_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }

            if candidate_config.sender.npb_dedup_enabled != new_config.sender.npb_dedup_enabled {
                if yaml_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }
            info!(
                "sender config change from {:#?} to {:#?}",
                candidate_config.sender, new_config.sender
            );
            candidate_config.sender = new_config.sender;
        }

        if candidate_config.handler != new_config.handler {
            if candidate_config.handler.npb_dedup_enabled != new_config.handler.npb_dedup_enabled {
                if yaml_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }
            info!(
                "handler config change from {:#?} to {:#?}",
                candidate_config.handler, new_config.handler
            );
            candidate_config.handler = new_config.handler;
        }

        if candidate_config.log_parser != new_config.log_parser {
            info!(
                "log_parser config change from {:#?} to {:#?}",
                candidate_config.log_parser, new_config.log_parser
            );

            if candidate_config.log_parser.l7_log_dynamic != new_config.log_parser.l7_log_dynamic {
                info!(
                    "l7 log dynamic config change from {:#?} to {:#?}",
                    candidate_config.log_parser.l7_log_dynamic,
                    new_config.log_parser.l7_log_dynamic
                );
                fn l7_log_dynamic_callback(_: &ConfigHandler, components: &mut Components) {
                    for log_parser in components.log_parsers.iter().as_ref() {
                        log_parser.l7_log_dynamic_config_updated();
                    }
                    if let Some(ebpf_collector) = components.ebpf_collector.as_mut() {
                        ebpf_collector.l7_log_dynamic_config_updated();
                    }
                }
                callbacks.push(l7_log_dynamic_callback);
            }
            if candidate_config.log_parser.l7_log_collect_nps_threshold
                != new_config.log_parser.l7_log_collect_nps_threshold
            {
                fn l7_log_collect_nps_threshold_callback(
                    config: &ConfigHandler,
                    components: &mut Components,
                ) {
                    info!(
                        "l7 log collect nps threshold set to {}",
                        config
                            .candidate_config
                            .log_parser
                            .l7_log_collect_nps_threshold
                    );
                    components.l7_log_rate.set_rate(Some(
                        config
                            .candidate_config
                            .log_parser
                            .l7_log_collect_nps_threshold,
                    ));
                }
                callbacks.push(l7_log_collect_nps_threshold_callback);
            }

            candidate_config.log_parser = new_config.log_parser;
        }

        if candidate_config.synchronizer != new_config.synchronizer {
            info!(
                "synchronizer config change from {:#?} to {:#?}",
                candidate_config.synchronizer, new_config.synchronizer
            );
            candidate_config.synchronizer = new_config.synchronizer;
        }

        if candidate_config.ebpf != new_config.ebpf {
            info!(
                "ebpf config change from {:#?} to {:#?}",
                candidate_config.ebpf, new_config.ebpf
            );
            candidate_config.ebpf = new_config.ebpf;

            fn ebpf_callback(handler: &ConfigHandler, components: &mut Components) {
                if let Some(ebpf_collector) = components.ebpf_collector.as_mut() {
                    ebpf_collector.on_config_change(&handler.candidate_config.ebpf);
                }
            }

            callbacks.push(ebpf_callback);
        }

        if candidate_config.stats != new_config.stats {
            info!(
                "stats config change from {:#?} to {:#?}",
                candidate_config.stats, new_config.stats
            );
            candidate_config.stats = new_config.stats;
        }

        if candidate_config.trident_type != new_config.trident_type {
            info!(
                "trident_type change from {:?} to {:?}",
                candidate_config.trident_type, new_config.trident_type
            );
            candidate_config.trident_type = new_config.trident_type;
        }

        if candidate_config.metric_server != new_config.metric_server {
            if candidate_config.metric_server.enabled != new_config.metric_server.enabled {
                fn metric_server_enabled_callback(
                    handler: &ConfigHandler,
                    components: &mut Components,
                ) {
                    if handler.candidate_config.metric_server.enabled {
                        components.external_metrics_server.start();
                    } else {
                        components.external_metrics_server.stop();
                    }
                }
                callbacks.push(metric_server_enabled_callback);
            }

            // 当端口更新后，在enabled情况下需要重启服务器重新监听
            if candidate_config.metric_server.port != new_config.metric_server.port {
                fn metric_server_port_callback(
                    handler: &ConfigHandler,
                    components: &mut Components,
                ) {
                    if handler.candidate_config.metric_server.enabled {
                        components.external_metrics_server.stop();
                        components.external_metrics_server.start();
                    }
                }
                callbacks.push(metric_server_port_callback);
            }
            info!(
                "integration collector config change from {:#?} to {:#?}",
                candidate_config.metric_server, new_config.metric_server
            );
            candidate_config.metric_server = new_config.metric_server;
        }

        //FIXME: 现在integration collector 在K8S环境下，会概率性出现监听端口一段时间后会失去监听。所以先探测下发的端口是否监听，
        // 没监听的话重启collector再监听。等找到根因后再去掉下面的代码
        // =============================================
        //FIXME: Now, in the K8S environment, the integration collector will probabilistically appear on the listening port and
        // lose monitoring after a period of time. So first detect whether the issued port is listening,
        // If not listening, restart the collector and listen again. After finding the root cause, remove the following code
        let port = candidate_config.metric_server.port;
        if candidate_config.metric_server.enabled && !check_listen_port_alive(port) {
            fn metric_server_restart_callback(_: &ConfigHandler, components: &mut Components) {
                components.external_metrics_server.stop();
                components.external_metrics_server.start();
            }
            callbacks.push(metric_server_restart_callback);
            warn!(
                "the port=({}) listen by the integration collector lost, restart the collector",
                candidate_config.metric_server.port
            );
        }

        if restart_dispatcher && candidate_config.dispatcher.enabled {
            fn dispatcher_callback(handler: &ConfigHandler, components: &mut Components) {
                for dispatcher in components.dispatchers.iter() {
                    dispatcher.stop();
                }
                match free_memory_check(
                    handler.candidate_config.environment.max_memory,
                    &components.exception_handler,
                ) {
                    Ok(()) => {
                        for dispatcher in components.dispatchers.iter() {
                            dispatcher.start();
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }
            }
            callbacks.push(dispatcher_callback);
        }

        // deploy updated config
        self.current_config
            .store(Arc::new(candidate_config.clone()));
        exception_handler.clear(Exception::InvalidConfiguration);

        callbacks
    }
}

impl YamlConfig {
    fn get_fast_path_map_size(&self, mem_size: u64) -> usize {
        if self.fast_path_map_size > 0 {
            return self.fast_path_map_size;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 20)
    }

    fn get_channel_size(&self, mem_size: u64) -> usize {
        if self.tap_mode == TapMode::Analyzer {
            return 1 << 14;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 14)
    }

    fn get_flow_capacity(&self, mem_size: u64) -> usize {
        if self.tap_mode == TapMode::Analyzer {
            return self.flow.capacity as usize;
        }

        min((mem_size / MB / 128 * 65536) as usize, 1 << 30)
    }

    fn get_af_packet_blocks(&self, mem_size: u64) -> usize {
        if self.tap_mode == TapMode::Analyzer || self.af_packet_blocks_enabled {
            self.af_packet_blocks.max(8)
        } else {
            (mem_size as usize / recv_engine::DEFAULT_BLOCK_SIZE / 16).min(128)
        }
    }
}
