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
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arc_swap::{access::Map, ArcSwap};
use bytesize::ByteSize;
use flexi_logger::writers::FileLogWriter;
use flexi_logger::{Age, Cleanup, Criterion, FileSpec, LoggerHandle, Naming};
use log::{info, warn, Level};
use sysinfo::SystemExt;

#[cfg(target_os = "linux")]
use super::{
    config::EbpfYamlConfig, OsProcRegexp, OS_PROC_REGEXP_MATCH_ACTION_ACCEPT,
    OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME,
};
use super::{
    config::{Config, PcapConfig, PortConfig, YamlConfig},
    ConfigError, IngressFlavour, KubernetesPollerType, RuntimeConfig,
};
use crate::{
    common::{decapsulate::TunnelTypeBitmap, enums::TapType, l7_protocol_log::L7ProtocolBitmap},
    dispatcher::recv_engine,
    exception::ExceptionHandler,
    flow_generator::{protocol_logs::SOFA_NEW_RPC_TRACE_CTX_KEY, FlowTimeout, TcpTimeout},
    handler::PacketHandlerBuilder,
    trident::{AgentComponents, RunningMode},
    utils::{
        environment::{free_memory_check, get_ctrl_ip_and_mac, running_in_container},
        logger::RemoteLogConfig,
    },
};
#[cfg(target_os = "linux")]
use crate::{
    dispatcher::recv_engine::af_packet::OptTpacketVersion,
    ebpf::CAP_LEN_MAX,
    platform::ProcRegRewrite,
    utils::{environment::is_tt_pod, environment::is_tt_workload},
};

use public::bitmap::Bitmap;
use public::proto::{
    common::TridentType,
    trident::{self, CaptureSocketType, Exception, IfMacSource, SocketType, TapMode},
};

use crate::utils::cgroups::is_kernel_available_for_cgroup;
#[cfg(target_os = "windows")]
use public::utils::net::links_by_name_regex;
use public::utils::net::MacAddr;

const MB: u64 = 1048576;
const MINUTE: Duration = Duration::from_secs(60);

type Access<C> = Map<Arc<ArcSwap<ModuleConfig>>, ModuleConfig, fn(&ModuleConfig) -> &C>;

pub type CollectorAccess = Access<CollectorConfig>;

pub type EnvironmentAccess = Access<EnvironmentConfig>;

pub type SenderAccess = Access<SenderConfig>;

pub type NpbAccess = Access<NpbConfig>;

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

#[cfg(target_os = "linux")]
pub type EbpfAccess = Access<EbpfConfig>;

pub type MetricServerAccess = Access<MetricServerConfig>;

pub type PortAccess = Access<PortConfig>;

#[derive(Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    pub enabled: bool,
    pub inactive_server_port_enabled: bool,
    pub inactive_ip_enabled: bool,
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
            .field("inactive_ip_enabled", &self.inactive_ip_enabled)
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
    pub dest_ip: String,
    pub vtap_id: u16,
    pub dest_port: u16,
    pub npb_port: u16,
    pub vxlan_flags: u8,
    pub npb_enable_qos_bypass: bool,
    pub npb_vlan: u16,
    pub npb_vlan_mode: trident::VlanMode,
    pub npb_dedup_enabled: bool,
    pub npb_bps_threshold: u64,
    pub npb_socket_type: trident::SocketType,
    pub collector_socket_type: trident::SocketType,
    pub standalone_data_file_size: u32,
    pub standalone_data_file_dir: String,
    pub server_tx_bandwidth_threshold: u64,
    pub bandwidth_probe_interval: Duration,
    pub enabled: bool,
}

impl Default for SenderConfig {
    fn default() -> Self {
        let module_config = ModuleConfig::default();
        return module_config.sender.clone();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NpbConfig {
    pub underlay_is_ipv6: bool,
    pub vxlan_flags: u8,
    pub npb_port: u16,
    pub dedup_enabled: bool,
    pub enable_qos_bypass: bool,
    pub output_vlan: u16,
    pub mtu: u32,
    pub vlan_mode: trident::VlanMode,
    pub socket_type: trident::SocketType,
}

impl Default for NpbConfig {
    fn default() -> Self {
        let module_config = ModuleConfig::default();
        return module_config.npb.clone();
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OsProcScanConfig {
    pub os_proc_root: String,
    pub os_proc_socket_sync_interval: u32, // for sec
    pub os_proc_socket_min_lifetime: u32,  // for sec
    pub os_proc_regex: Vec<ProcRegRewrite>,
    pub os_app_tag_exec_user: String,
    pub os_app_tag_exec: Vec<String>,
    // whether to sync os socket and proc info
    // only make sense when process_info_enabled() == true
    pub os_proc_sync_enabled: bool,
}
#[cfg(target_os = "windows")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OsProcScanConfig;

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
    pub kubernetes_api_list_limit: u32,
    pub kubernetes_api_list_interval: Duration,
    pub namespace: Option<String>,
    pub thread_threshold: u32,
    pub tap_mode: TapMode,
    pub os_proc_scan_conf: OsProcScanConfig,
}

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct HandlerConfig {
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
    #[cfg(target_os = "linux")]
    pub extra_netns_regex: String,
    pub tap_interface_regex: String,
    pub if_mac_source: IfMacSource,
    pub analyzer_ip: String,
    pub analyzer_port: u16,
    pub proxy_controller_ip: String,
    pub proxy_controller_port: u16,
    pub capture_bpf: String,
    pub max_memory: u64,
    pub af_packet_blocks: usize,
    #[cfg(target_os = "linux")]
    pub af_packet_version: OptTpacketVersion,
    pub tap_mode: TapMode,
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub enabled: bool,
    pub npb_dedup_enabled: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LogConfig {
    pub log_level: Level,
    pub log_threshold: u32,
    pub log_retention: u32,
    pub rsyslog_enabled: bool,
    pub host: String,
    pub analyzer_ip: String,
    pub analyzer_port: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FlowConfig {
    pub vtap_id: u16,
    pub trident_type: TridentType,
    pub cloud_gateway_traffic: bool,
    pub collector_enabled: bool,
    pub l7_log_tap_types: [bool; 256],

    pub hash_slots: u32,
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

    pub l7_protocol_enabled_bitmap: L7ProtocolBitmap,

    // vec<protocolName, port bitmap>
    pub l7_protocol_parse_port_bitmap: Arc<Vec<(String, Bitmap)>>,
}

impl From<&RuntimeConfig> for FlowConfig {
    fn from(conf: &RuntimeConfig) -> Self {
        let flow_config = &conf.yaml_config.flow;
        FlowConfig {
            vtap_id: conf.vtap_id as u16,
            trident_type: conf.trident_type,
            cloud_gateway_traffic: conf.yaml_config.cloud_gateway_traffic,
            collector_enabled: conf.collector_enabled,
            l7_log_tap_types: {
                let mut tap_types = [false; 256];
                for &t in conf.l7_log_store_tap_types.iter() {
                    if (t as u16) >= u16::from(TapType::Max) {
                        warn!("invalid tap type: {}", t);
                    } else {
                        tap_types[t as usize] = true;
                    }
                }
                tap_types
            },
            hash_slots: flow_config.hash_slots,
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
            l7_protocol_enabled_bitmap: L7ProtocolBitmap::from(
                &conf.yaml_config.l7_protocol_enabled,
            ),
            l7_protocol_parse_port_bitmap: Arc::new(
                (&conf.yaml_config).get_protocol_port_parse_bitmap(),
            ),
        }
    }
}

impl fmt::Debug for FlowConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowConfig")
            .field("vtap_id", &self.vtap_id)
            .field("trident_type", &self.trident_type)
            .field("cloud_gateway_traffic", &self.cloud_gateway_traffic)
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
            .field("hash_slots", &self.hash_slots)
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
            .field("packet_sequence_flag", &self.packet_sequence_flag)
            .field(
                "packet_sequence_block_size",
                &self.packet_sequence_block_size,
            )
            .field(
                "l7_protocol_enabled_bitmap",
                &self.l7_protocol_enabled_bitmap,
            )
            // FIXME: this field is too long to log
            // .field("l7_protocol_parse_port_bitmap", &self.l7_protocol_parse_port_bitmap)
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
    pub controller_port: u16,
    pub listen_port: u16,
    pub agent_mode: RunningMode,
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
    pub analyzer_ip: String,
    pub analyzer_port: u16,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SynchronizerConfig {
    pub sync_interval: Duration,
    pub ntp_enabled: bool,
    pub max_escape: Duration,
    pub output_vlan: u16,
}

#[cfg(target_os = "linux")]
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
    pub l7_log_tap_types: [bool; 256],
    pub ctrl_mac: MacAddr,
    pub l7_protocol_enabled_bitmap: L7ProtocolBitmap,
    pub l7_protocol_parse_port_bitmap: Arc<Vec<(String, Bitmap)>>,
    pub l7_protocol_ports: HashMap<String, String>,
    pub ebpf: EbpfYamlConfig,
}

#[cfg(target_os = "linux")]
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
            .field(
                "l7_log_tap_types",
                &self
                    .l7_log_tap_types
                    .iter()
                    .enumerate()
                    .filter(|&(_, b)| *b)
                    .collect::<Vec<_>>(),
            )
            .field("ctrl_mac", &self.ctrl_mac)
            .field(
                "l7_protocol_enabled_bitmap",
                &self.l7_protocol_enabled_bitmap,
            )
            .field("l7_protocol_ports", &self.l7_protocol_ports)
            .field("ebpf", &self.ebpf)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl EbpfConfig {
    pub fn l7_log_enabled(&self) -> bool {
        // disabled when metrics collection is turned off
        if !self.l7_metrics_enabled || !self.collector_enabled {
            return false;
        }
        // eBPF data is only collected from Cloud-type TAP
        return self.l7_log_tap_types[u16::from(TapType::Any) as usize]
            || self.l7_log_tap_types[u16::from(TapType::Cloud) as usize];
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
    NewRpcTraceContext,
    Customize(String),
}

// The value here must be lower case
const TRACE_TYPE_XB3: &str = "x-b3-traceid";
const TRACE_TYPE_XB3SPAN: &str = "x-b3-spanid";
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
        let format_t = Self::format_str(t);
        match format_t.to_lowercase().as_str() {
            TRACE_TYPE_XB3 => TraceType::XB3,
            TRACE_TYPE_XB3SPAN => TraceType::XB3Span,
            TRACE_TYPE_UBER => TraceType::Uber,
            TRACE_TYPE_SW6 => TraceType::Sw6,
            TRACE_TYPE_SW8 => TraceType::Sw8,
            TRACE_TYPE_TRACE_PARENT => TraceType::TraceParent,
            SOFA_NEW_RPC_TRACE_CTX_KEY => TraceType::NewRpcTraceContext,
            _ if t.len() > 0 => TraceType::Customize(format_t.to_string()),
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
            TraceType::XB3 => context.to_ascii_lowercase() == TRACE_TYPE_XB3,
            TraceType::XB3Span => context.to_ascii_lowercase() == TRACE_TYPE_XB3SPAN,
            TraceType::Uber => context.to_ascii_lowercase() == TRACE_TYPE_UBER,
            TraceType::Sw6 => context.to_ascii_lowercase() == TRACE_TYPE_SW6,
            TraceType::Sw8 => context.to_ascii_lowercase() == TRACE_TYPE_SW8,
            TraceType::TraceParent => context.to_ascii_lowercase() == TRACE_TYPE_TRACE_PARENT,
            TraceType::NewRpcTraceContext => {
                context.to_ascii_lowercase() == SOFA_NEW_RPC_TRACE_CTX_KEY
            }
            TraceType::Customize(tag) => context.to_ascii_lowercase() == tag.to_ascii_lowercase(),
            _ => false,
        }
    }

    pub fn to_checker_string(&self) -> String {
        match self {
            &TraceType::XB3 => TRACE_TYPE_XB3.into(),
            &TraceType::XB3Span => TRACE_TYPE_XB3SPAN.into(),
            &TraceType::Uber => TRACE_TYPE_UBER.into(),
            &TraceType::Sw6 => TRACE_TYPE_SW6.into(),
            &TraceType::Sw8 => TRACE_TYPE_SW8.into(),
            &TraceType::TraceParent => TRACE_TYPE_TRACE_PARENT.into(),
            &TraceType::NewRpcTraceContext => SOFA_NEW_RPC_TRACE_CTX_KEY.into(),
            &TraceType::Customize(ref tag) => tag.to_ascii_lowercase(),
            _ => "".into(),
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

#[derive(Default, Clone, Debug)]
pub struct L7LogDynamicConfig {
    // in lowercase
    pub proxy_client: String,
    // in lowercase
    pub x_request_id: String,

    pub trace_types: Vec<TraceType>,
    pub span_types: Vec<TraceType>,

    trace_set: HashSet<String>,
    span_set: HashSet<String>,
}

impl PartialEq for L7LogDynamicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.proxy_client == other.proxy_client
            && self.x_request_id == other.x_request_id
            && self.trace_types == other.trace_types
            && self.span_types == other.span_types
    }
}

impl Eq for L7LogDynamicConfig {}

impl L7LogDynamicConfig {
    pub fn new(
        mut proxy_client: String,
        mut x_request_id: String,
        trace_types: Vec<TraceType>,
        span_types: Vec<TraceType>,
    ) -> Self {
        proxy_client.make_ascii_lowercase();
        x_request_id.make_ascii_lowercase();

        let mut trace_set = HashSet::new();
        for t in trace_types.iter() {
            trace_set.insert(t.to_checker_string());
        }

        let mut span_set = HashSet::new();
        for t in span_types.iter() {
            span_set.insert(t.to_checker_string());
        }

        Self {
            proxy_client,
            x_request_id,
            trace_types,
            span_types,
            trace_set,
            span_set,
        }
    }

    pub fn is_trace_id(&self, context: &str) -> bool {
        self.trace_set.contains(context)
    }

    pub fn is_span_id(&self, context: &str) -> bool {
        self.span_set.contains(context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricServerConfig {
    pub enabled: bool,
    pub port: u16,
    pub compressed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub tap_mode: TapMode,
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
    pub npb: NpbConfig,
    pub handler: HandlerConfig,
    pub log: LogConfig,
    pub synchronizer: SynchronizerConfig,
    #[cfg(target_os = "linux")]
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
        #[cfg(target_os = "linux")]
        let (ctrl_ip, ctrl_mac) =
            get_ctrl_ip_and_mac(static_config.controller_ips[0].parse().unwrap());
        #[cfg(target_os = "windows")]
        let (ctrl_ip, _) = get_ctrl_ip_and_mac(static_config.controller_ips[0].parse().unwrap());
        let dest_ip = if conf.analyzer_ip.len() > 0 {
            conf.analyzer_ip.clone()
        } else {
            "0.0.0.0".to_string()
        };
        let proxy_controller_ip = if conf.proxy_controller_ip.len() > 0 {
            conf.proxy_controller_ip.clone()
        } else {
            static_config.controller_ips[0].clone()
        };

        let config = ModuleConfig {
            enabled: conf.enabled,
            yaml_config: conf.yaml_config.clone(),
            tap_mode: conf.tap_mode,
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
                sync_interval: Duration::from_secs(conf.sync_interval),
                output_vlan: conf.output_vlan,
                ntp_enabled: conf.ntp_enabled,
                max_escape: Duration::from_secs(conf.max_escape),
            },
            stats: StatsConfig {
                interval: Duration::from_secs(conf.stats_interval),
                host: conf.host.clone(),
                analyzer_ip: dest_ip.clone(),
                analyzer_port: conf.analyzer_port,
            },
            dispatcher: DispatcherConfig {
                global_pps_threshold: conf.global_pps_threshold,
                capture_packet_size: conf.capture_packet_size,
                l7_log_packet_size: conf.l7_log_packet_size,
                tunnel_type_bitmap: TunnelTypeBitmap::new(&conf.decap_types),
                trident_type: conf.trident_type,
                vtap_id: conf.vtap_id as u16,
                capture_socket_type: conf.capture_socket_type,
                #[cfg(target_os = "linux")]
                extra_netns_regex: conf.extra_netns_regex.to_string(),
                tap_interface_regex: conf.tap_interface_regex.to_string(),
                if_mac_source: conf.if_mac_source,
                analyzer_ip: dest_ip.clone(),
                analyzer_port: conf.analyzer_port,
                proxy_controller_ip,
                proxy_controller_port: conf.proxy_controller_port,
                capture_bpf: conf.capture_bpf.to_string(),
                max_memory: conf.max_memory,
                af_packet_blocks: conf
                    .yaml_config
                    .get_af_packet_blocks(conf.tap_mode, conf.max_memory),
                #[cfg(target_os = "linux")]
                af_packet_version: conf.capture_socket_type.into(),
                tap_mode: conf.tap_mode,
                region_id: conf.region_id,
                pod_cluster_id: conf.pod_cluster_id,
                enabled: conf.enabled,
                npb_dedup_enabled: conf.npb_dedup_enabled,
            },
            sender: SenderConfig {
                mtu: conf.mtu,
                dest_ip: dest_ip.clone(),
                vtap_id: conf.vtap_id as u16,
                dest_port: conf.analyzer_port,
                npb_port: conf.yaml_config.npb_port,
                vxlan_flags: conf.yaml_config.vxlan_flags,
                npb_enable_qos_bypass: conf.yaml_config.enable_qos_bypass,
                npb_vlan: conf.output_vlan,
                npb_vlan_mode: conf.npb_vlan_mode,
                npb_dedup_enabled: conf.npb_dedup_enabled,
                npb_bps_threshold: conf.npb_bps_threshold,
                npb_socket_type: conf.npb_socket_type,
                server_tx_bandwidth_threshold: conf.server_tx_bandwidth_threshold,
                bandwidth_probe_interval: conf.bandwidth_probe_interval,
                collector_socket_type: conf.collector_socket_type,
                standalone_data_file_size: conf.yaml_config.standalone_data_file_size,
                standalone_data_file_dir: conf.yaml_config.standalone_data_file_dir.clone(),
                enabled: conf.collector_enabled,
            },
            npb: NpbConfig {
                mtu: conf.mtu,
                underlay_is_ipv6: ctrl_ip.is_ipv6(),
                npb_port: conf.yaml_config.npb_port,
                vxlan_flags: conf.yaml_config.vxlan_flags,
                enable_qos_bypass: conf.yaml_config.enable_qos_bypass,
                output_vlan: conf.output_vlan,
                vlan_mode: conf.npb_vlan_mode,
                dedup_enabled: conf.npb_dedup_enabled,
                socket_type: conf.npb_socket_type,
            },
            collector: CollectorConfig {
                enabled: conf.collector_enabled,
                inactive_server_port_enabled: conf.inactive_server_port_enabled,
                inactive_ip_enabled: conf.inactive_ip_enabled,
                vtap_flow_1s_enabled: conf.vtap_flow_1s_enabled,
                l4_log_collect_nps_threshold: conf.l4_log_collect_nps_threshold,
                l7_metrics_enabled: conf.l7_metrics_enabled,
                trident_type: conf.trident_type,
                vtap_id: conf.vtap_id as u16,
                l4_log_store_tap_types: {
                    let mut tap_types = [false; 256];
                    for &t in conf.l4_log_store_tap_types.iter() {
                        if (t as u16) >= u16::from(TapType::Max) {
                            warn!("invalid tap type: {}", t);
                        } else {
                            tap_types[t as usize] = true;
                        }
                    }
                    tap_types
                },
                cloud_gateway_traffic: conf.yaml_config.cloud_gateway_traffic,
            },
            handler: HandlerConfig {
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
                kubernetes_api_list_limit: conf.yaml_config.kubernetes_api_list_limit,
                kubernetes_api_list_interval: conf.yaml_config.kubernetes_api_list_interval,
                namespace: if conf.yaml_config.kubernetes_namespace.is_empty() {
                    None
                } else {
                    Some(conf.yaml_config.kubernetes_namespace.clone())
                },
                thread_threshold: conf.thread_threshold,
                tap_mode: conf.tap_mode,
                #[cfg(target_os = "linux")]
                os_proc_scan_conf: OsProcScanConfig {
                    os_proc_root: conf.yaml_config.os_proc_root.clone(),
                    os_proc_socket_sync_interval: conf.yaml_config.os_proc_socket_sync_interval,
                    os_proc_socket_min_lifetime: conf.yaml_config.os_proc_socket_min_lifetime,
                    os_proc_regex: {
                        let mut v = vec![];
                        for i in &conf.yaml_config.os_proc_regex {
                            if let Ok(r) = ProcRegRewrite::try_from(i) {
                                v.push(r);
                            }
                        }

                        // append the .* at the end for accept the proc whic not match any regexp
                        v.push(
                            ProcRegRewrite::try_from(&OsProcRegexp {
                                match_regex: ".*".into(),
                                match_type: OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME.into(),
                                rewrite_name: "".into(),
                                action: OS_PROC_REGEXP_MATCH_ACTION_ACCEPT.into(),
                            })
                            .unwrap(),
                        );
                        v
                    },
                    os_app_tag_exec_user: conf.yaml_config.os_app_tag_exec_user.clone(),
                    os_app_tag_exec: conf.yaml_config.os_app_tag_exec.clone(),
                    os_proc_sync_enabled: conf.yaml_config.os_proc_sync_enabled,
                },
                #[cfg(target_os = "windows")]
                os_proc_scan_conf: OsProcScanConfig {},
            },
            flow: (&conf).into(),
            log_parser: LogParserConfig {
                l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold,
                l7_log_session_aggr_timeout: conf.yaml_config.l7_log_session_aggr_timeout,
                l7_log_dynamic: L7LogDynamicConfig::new(
                    conf.http_log_proxy_client.to_string().to_ascii_lowercase(),
                    conf.http_log_x_request_id.to_string().to_ascii_lowercase(),
                    conf.http_log_trace_id
                        .split(',')
                        .map(|item| TraceType::from(item))
                        .collect(),
                    conf.http_log_span_id
                        .split(',')
                        .map(|item| TraceType::from(item))
                        .collect(),
                ),
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
                controller_port: static_config.controller_port,
                agent_mode: static_config.agent_mode,
            },
            log: LogConfig {
                log_level: conf.log_level,
                log_threshold: conf.log_threshold,
                log_retention: conf.log_retention,
                rsyslog_enabled: conf.rsyslog_enabled,
                host: conf.host.clone(),
                analyzer_ip: dest_ip.clone(),
                analyzer_port: conf.analyzer_port,
            },
            #[cfg(target_os = "linux")]
            ebpf: EbpfConfig {
                collector_enabled: conf.collector_enabled,
                l7_metrics_enabled: conf.l7_metrics_enabled,
                vtap_id: conf.vtap_id as u16,
                epc_id: conf.epc_id,
                l7_log_session_timeout: conf.yaml_config.l7_log_session_aggr_timeout,
                l7_log_packet_size: CAP_LEN_MAX.min(conf.l7_log_packet_size as usize),
                l7_log_tap_types: {
                    let mut tap_types = [false; 256];
                    for &t in conf.l7_log_store_tap_types.iter() {
                        if (t as u16) >= u16::from(TapType::Max) {
                            warn!("invalid tap type: {}", t);
                        } else {
                            tap_types[t as usize] = true;
                        }
                    }
                    tap_types
                },
                l7_protocol_inference_max_fail_count: conf
                    .yaml_config
                    .l7_protocol_inference_max_fail_count,
                l7_protocol_inference_ttl: conf.yaml_config.l7_protocol_inference_ttl,
                ctrl_mac: if is_tt_workload(conf.trident_type) {
                    ctrl_mac
                } else {
                    MacAddr::ZERO
                },
                l7_protocol_enabled_bitmap: L7ProtocolBitmap::from(
                    &conf.yaml_config.l7_protocol_enabled,
                ),
                l7_protocol_parse_port_bitmap: Arc::new(
                    (&conf.yaml_config).get_protocol_port_parse_bitmap(),
                ),
                l7_protocol_ports: conf.yaml_config.l7_protocol_ports.clone(),
                ebpf: conf.yaml_config.ebpf.clone(),
            },
            metric_server: MetricServerConfig {
                enabled: conf.external_agent_http_proxy_enabled,
                port: conf.external_agent_http_proxy_port as u16,
                compressed: conf.yaml_config.external_agent_http_proxy_compressed,
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

    pub fn npb(&self) -> NpbAccess {
        Map::new(self.current_config.clone(), |config| -> &NpbConfig {
            &config.npb
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

    #[cfg(target_os = "linux")]
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
        mut components: Option<&mut AgentComponents>,
    ) -> Vec<fn(&ConfigHandler, &mut AgentComponents)> {
        let candidate_config = &mut self.candidate_config;
        let static_config = &self.static_config;
        let yaml_config = &mut candidate_config.yaml_config;
        let mut new_config: ModuleConfig = (static_config.clone(), new_config).try_into().unwrap();
        let mut callbacks: Vec<fn(&ConfigHandler, &mut AgentComponents)> = vec![];
        let mut restart_dispatcher = false;

        if candidate_config.tap_mode != new_config.tap_mode {
            info!("tap_mode set to {:?}", new_config.tap_mode);
            candidate_config.tap_mode = new_config.tap_mode;
        }

        if candidate_config.tap_mode != TapMode::Analyzer
            && !running_in_container()
            && !is_kernel_available_for_cgroup()
        // In the environment where cgroup is not supported, we need to check free memory
        {
            // Check and send out exceptions in time
            if let Err(e) = free_memory_check(new_config.environment.max_memory, exception_handler)
            {
                warn!("{}", e);
            }
        }

        if !yaml_config
            .src_interfaces
            .eq(&new_config.yaml_config.src_interfaces)
        {
            yaml_config
                .src_interfaces
                .clone_from(&new_config.yaml_config.src_interfaces);
            info!("src_interfaces set to {:?}", yaml_config.src_interfaces);
        }

        if candidate_config.tap_mode != TapMode::Local && yaml_config.src_interfaces.is_empty() {
            warn!("src_interfaces should be set in Analyzer mode or Mirror mode");
        }

        if yaml_config.analyzer_dedup_disabled != new_config.yaml_config.analyzer_dedup_disabled {
            yaml_config.analyzer_dedup_disabled = new_config.yaml_config.analyzer_dedup_disabled;
            info!(
                "analyzer_dedup_disabled set to {:?}",
                yaml_config.analyzer_dedup_disabled
            );
        }

        if yaml_config.mirror_traffic_pcp != new_config.yaml_config.mirror_traffic_pcp {
            yaml_config.mirror_traffic_pcp = new_config.yaml_config.mirror_traffic_pcp;
            info!(
                "mirror_traffic_pcp set to {:?}",
                yaml_config.mirror_traffic_pcp
            );
        }

        if *yaml_config != new_config.yaml_config {
            *yaml_config = new_config.yaml_config;
        }

        if candidate_config.dispatcher != new_config.dispatcher {
            #[cfg(target_os = "linux")]
            if candidate_config.dispatcher.extra_netns_regex
                != new_config.dispatcher.extra_netns_regex
            {
                info!(
                    "extra_netns_regex set to: {:?}",
                    new_config.dispatcher.extra_netns_regex
                );
                if let Some(c) = components.as_ref() {
                    c.platform_synchronizer
                        .set_netns_regex(&new_config.dispatcher.extra_netns_regex);
                }
            }

            if candidate_config.dispatcher.if_mac_source != new_config.dispatcher.if_mac_source {
                if candidate_config.tap_mode != TapMode::Local {
                    info!(
                        "if_mac_source set to {:?}",
                        new_config.dispatcher.if_mac_source
                    );
                }
            }

            #[cfg(target_os = "windows")]
            if candidate_config.tap_mode == TapMode::Local
                && candidate_config.dispatcher.tap_interface_regex
                    != new_config.dispatcher.tap_interface_regex
            {
                fn switch_recv_engine(handler: &ConfigHandler, comp: &mut AgentComponents) {
                    let pcap_interfaces = match links_by_name_regex(
                        &handler.candidate_config.dispatcher.tap_interface_regex,
                    ) {
                        Err(e) => {
                            warn!("get interfaces by name regex failed: {}", e);
                            vec![]
                        }
                        Ok(links) => links,
                    };
                    for dispatcher in comp.dispatchers.iter() {
                        dispatcher.switch_recv_engine(pcap_interfaces.clone());
                    }
                }
                callbacks.push(switch_recv_engine);
            }

            if candidate_config.dispatcher.capture_packet_size
                != new_config.dispatcher.capture_packet_size
            {
                candidate_config.dispatcher.capture_packet_size =
                    new_config.dispatcher.capture_packet_size;
                if !components.is_none() {
                    info!("Capture packet size update, deepflow-agent restart...");
                    thread::sleep(Duration::from_secs(1));
                    process::exit(1);
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
                    fn start_dispatcher(handler: &ConfigHandler, components: &mut AgentComponents) {
                        match handler.candidate_config.tap_mode {
                            TapMode::Analyzer => {
                                for dispatcher in components.dispatchers.iter() {
                                    dispatcher.start();
                                }
                            }
                            _ => {
                                if !running_in_container() && !is_kernel_available_for_cgroup() {
                                    // In the environment where cgroup is not supported, we need to check free memory
                                    match free_memory_check(
                                        // fixme: It can skip this check because it has been checked before
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
                            }
                        }
                    }
                    callbacks.push(start_dispatcher);
                } else {
                    fn stop_dispatcher(_: &ConfigHandler, components: &mut AgentComponents) {
                        for dispatcher in components.dispatchers.iter() {
                            dispatcher.stop();
                        }
                    }
                    callbacks.push(stop_dispatcher);
                }
            }

            if candidate_config.dispatcher.max_memory != new_config.dispatcher.max_memory {
                if yaml_config
                    .get_af_packet_blocks(new_config.tap_mode, new_config.dispatcher.max_memory)
                    != yaml_config.get_af_packet_blocks(
                        candidate_config.tap_mode,
                        candidate_config.dispatcher.max_memory,
                    )
                    || yaml_config.get_fast_path_map_size(new_config.dispatcher.max_memory)
                        != yaml_config
                            .get_fast_path_map_size(candidate_config.dispatcher.max_memory)
                    || candidate_config.get_channel_size(new_config.dispatcher.max_memory)
                        != candidate_config.get_channel_size(candidate_config.dispatcher.max_memory)
                    || candidate_config.get_flow_capacity(new_config.dispatcher.max_memory)
                        != candidate_config
                            .get_flow_capacity(candidate_config.dispatcher.max_memory)
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

                fn leaky_bucket_callback(
                    handler: &ConfigHandler,
                    components: &mut AgentComponents,
                ) {
                    match handler.candidate_config.tap_mode {
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
            if candidate_config.log.analyzer_ip != new_config.log.analyzer_ip
                || candidate_config.log.analyzer_port != new_config.log.analyzer_port
            {
                info!(
                    "Rsyslog client connect to {} {}",
                    &new_config.log.analyzer_ip, new_config.log.analyzer_port
                );
                self.remote_log_config.set_remotes(
                    &vec![new_config.log.analyzer_ip.clone()],
                    new_config.log.analyzer_port,
                );
            }
            candidate_config.log = new_config.log;
        }

        if candidate_config.stats != new_config.stats {
            info!(
                "stats config change from {:#?} to {:#?}",
                candidate_config.stats, new_config.stats
            );
            candidate_config.stats = new_config.stats;

            fn stats_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
                let c = &components.stats_collector;
                c.set_hostname(handler.candidate_config.stats.host.clone());
                c.set_min_interval(handler.candidate_config.stats.interval);
                c.set_remote(
                    handler.candidate_config.stats.analyzer_ip.clone(),
                    handler.candidate_config.stats.analyzer_port,
                );
            }
            callbacks.push(stats_callback);
        }

        if candidate_config.debug != new_config.debug {
            info!(
                "debug config change from {:#?} to {:#?}",
                candidate_config.debug, new_config.debug
            );
            candidate_config.debug = new_config.debug;

            fn debug_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
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

        if candidate_config.environment.max_memory != new_config.environment.max_memory {
            if let Some(ref components) = components {
                components
                    .policy_setter
                    .set_memory_limit(new_config.environment.max_memory);
            }
        }

        if candidate_config.tap_mode != TapMode::Analyzer && !running_in_container() {
            if candidate_config.environment.max_memory != new_config.environment.max_memory {
                info!(
                    "memory limit set to {}",
                    ByteSize::b(new_config.environment.max_memory).to_string_as(true)
                );
                candidate_config.environment.max_memory = new_config.environment.max_memory;
            }

            if candidate_config.environment.max_cpus != new_config.environment.max_cpus {
                info!("cpu limit set to {}", new_config.environment.max_cpus);
                candidate_config.environment.max_cpus = new_config.environment.max_cpus;
            }
        } else if candidate_config.tap_mode == TapMode::Analyzer || running_in_container() {
            let mut system = sysinfo::System::new();
            system.refresh_memory();
            let max_memory = system.total_memory();
            system.refresh_cpu();
            let max_cpus = 1.max(system.cpus().len()) as u32;

            if candidate_config.environment.max_memory != max_memory {
                info!("memory set ulimit when tap_mode=analyzer or running in a K8s pod");
                candidate_config.environment.max_memory = max_memory;
            }

            if candidate_config.environment.max_cpus != max_cpus {
                info!("cpu set ulimit when tap_mode=analyzer or running in a K8s pod");
                candidate_config.environment.max_cpus = max_cpus;
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

        if candidate_config.environment.process_threshold
            != new_config.environment.process_threshold
        {
            info!(
                "process_threshold set to {}",
                new_config.environment.process_threshold
            );
            candidate_config.environment.process_threshold =
                new_config.environment.process_threshold;
        }

        if candidate_config.environment.thread_threshold != new_config.environment.thread_threshold
        {
            info!(
                "thread_threshold set to {}",
                new_config.environment.thread_threshold
            );
            candidate_config.environment.thread_threshold = new_config.environment.thread_threshold;
        }

        if candidate_config.environment.log_file_size != new_config.environment.log_file_size {
            info!(
                "log_file_size set to {}",
                new_config.environment.log_file_size
            );
            candidate_config.environment.log_file_size = new_config.environment.log_file_size;
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

            fn quadruple_generator_callback(_: &ConfigHandler, components: &mut AgentComponents) {
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
            let old_cfg = &candidate_config.platform;
            let new_cfg = &new_config.platform;

            if old_cfg.enabled != new_cfg.enabled {
                info!("Platform enabled set to {}", new_cfg.enabled);
            }
            if old_cfg.kubernetes_api_list_limit != new_cfg.kubernetes_api_list_limit {
                info!(
                    "Kubernetes API list limit set to {}",
                    new_cfg.kubernetes_api_list_limit
                );
            }
            if old_cfg.kubernetes_api_list_interval != new_cfg.kubernetes_api_list_interval {
                info!(
                    "Kubernetes API list interval set to {:?}",
                    new_cfg.kubernetes_api_list_interval
                );
            }
            if old_cfg.kubernetes_api_enabled != new_cfg.kubernetes_api_enabled {
                info!(
                    "Kubernetes API enabled set to {}",
                    new_cfg.kubernetes_api_enabled
                );
            }

            // restart api watcher if it keeps running and config changes
            #[cfg(target_os = "linux")]
            let restart_api_watcher = old_cfg.kubernetes_api_enabled
                && new_cfg.kubernetes_api_enabled
                && (old_cfg.kubernetes_api_list_limit != new_cfg.kubernetes_api_list_limit
                    || old_cfg.kubernetes_api_list_interval
                        != new_cfg.kubernetes_api_list_interval);

            info!(
                "platform config change from {:#?} to {:#?}",
                candidate_config.platform, new_config.platform
            );
            candidate_config.platform = new_config.platform;

            #[cfg(target_os = "linux")]
            if static_config.agent_mode == RunningMode::Managed {
                fn platform_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
                    let conf = &handler.candidate_config.platform;

                    if handler.candidate_config.enabled
                        && (handler.candidate_config.tap_mode == TapMode::Local
                            || is_tt_pod(conf.trident_type))
                    {
                        if is_tt_pod(conf.trident_type) {
                            components.platform_synchronizer.start_kubernetes_poller();
                        } else {
                            components.platform_synchronizer.stop_kubernetes_poller();
                        }
                        if conf.kubernetes_api_enabled {
                            components.api_watcher.start();
                        } else {
                            components.api_watcher.stop();
                        }
                    }
                    if conf.kubernetes_api_enabled {
                        components.api_watcher.start();
                    } else {
                        components.api_watcher.stop();
                    }
                }
                callbacks.push(platform_callback);
                if restart_api_watcher {
                    callbacks.push(|_, components| {
                        components.api_watcher.stop();
                        components.api_watcher.start();
                    })
                }
            }
        }

        if candidate_config.sender != new_config.sender {
            if candidate_config.sender.collector_socket_type
                != new_config.sender.collector_socket_type
            {
                if candidate_config.sender.enabled != new_config.sender.enabled {
                    restart_dispatcher = true;
                }
            }

            if candidate_config.sender.npb_socket_type != new_config.sender.npb_socket_type {
                if candidate_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }

            if candidate_config.sender.npb_dedup_enabled != new_config.sender.npb_dedup_enabled {
                if candidate_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }

            if let Some(components) = &components {
                if candidate_config.sender.bandwidth_probe_interval
                    != new_config.sender.bandwidth_probe_interval
                {
                    info!(
                        "Npb tx interface bandwidth probe interval set to {}s.",
                        new_config.sender.bandwidth_probe_interval.as_secs()
                    );
                    components
                        .npb_bandwidth_watcher
                        .set_interval(new_config.sender.bandwidth_probe_interval.as_secs());
                }
                if candidate_config.sender.server_tx_bandwidth_threshold
                    != new_config.sender.server_tx_bandwidth_threshold
                {
                    info!(
                        "Npb tx interface bandwidth threshold set to {}.",
                        new_config.sender.server_tx_bandwidth_threshold
                    );
                    components
                        .npb_bandwidth_watcher
                        .set_nic_rate(new_config.sender.server_tx_bandwidth_threshold);
                }
                if candidate_config.sender.npb_bps_threshold != new_config.sender.npb_bps_threshold
                {
                    info!(
                        "Npb bps threshold set to {}.",
                        new_config.sender.npb_bps_threshold
                    );
                    components
                        .npb_bandwidth_watcher
                        .set_npb_rate(new_config.sender.npb_bps_threshold);
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
                if candidate_config.tap_mode != TapMode::Analyzer {
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
            }
            if candidate_config.log_parser.l7_log_collect_nps_threshold
                != new_config.log_parser.l7_log_collect_nps_threshold
            {
                fn l7_log_collect_nps_threshold_callback(
                    config: &ConfigHandler,
                    components: &mut AgentComponents,
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

        #[cfg(target_os = "linux")]
        if candidate_config.ebpf != new_config.ebpf
            && candidate_config.tap_mode != TapMode::Analyzer
        {
            info!(
                "ebpf config change from {:#?} to {:#?}",
                candidate_config.ebpf, new_config.ebpf
            );
            candidate_config.ebpf = new_config.ebpf;

            fn ebpf_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
                if let Some(ebpf_collector) = components.ebpf_collector.as_mut() {
                    ebpf_collector.on_config_change(&handler.candidate_config.ebpf);
                }
            }
            callbacks.push(ebpf_callback);
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
                if let Some(c) = components.as_mut() {
                    if new_config.metric_server.enabled {
                        c.external_metrics_server.start();
                    } else {
                        c.external_metrics_server.stop();
                    }
                }
            }

            // 当端口更新后，在enabled情况下需要重启服务器重新监听
            if candidate_config.metric_server.port != new_config.metric_server.port {
                if let Some(c) = components.as_mut() {
                    c.external_metrics_server
                        .set_port(new_config.metric_server.port);
                }
            }
            if candidate_config.metric_server.compressed != new_config.metric_server.compressed {
                fn metric_server_callback(
                    handler: &ConfigHandler,
                    components: &mut AgentComponents,
                ) {
                    components
                        .external_metrics_server
                        .enable_compressed(handler.candidate_config.metric_server.compressed);
                }
                callbacks.push(metric_server_callback);
            }
            info!(
                "integration collector config change from {:#?} to {:#?}",
                candidate_config.metric_server, new_config.metric_server
            );
            candidate_config.metric_server = new_config.metric_server;
        }

        if candidate_config.npb != new_config.npb {
            fn dispatcher_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
                let dispatcher_builders = &components.handler_builders;
                for e in dispatcher_builders {
                    let mut builders = e.lock().unwrap();
                    for e in builders.iter_mut() {
                        match e {
                            PacketHandlerBuilder::Npb(n) => {
                                n.on_config_change(
                                    &handler.candidate_config.npb,
                                    &components.debugger.clone_queue(),
                                );
                            }
                            _ => {}
                        }
                    }
                }
                components.npb_arp_table.set_need_resolve_mac(
                    handler.candidate_config.npb.socket_type == SocketType::RawUdp,
                );
            }
            if components.is_some() {
                callbacks.push(dispatcher_callback);
            }
            info!(
                "npb config change from {:#?} to {:#?}",
                candidate_config.npb, new_config.npb
            );
            candidate_config.npb = new_config.npb;
            restart_dispatcher = true;
        }

        // avoid first config changed to restart dispatcher
        if components.is_some() && restart_dispatcher && candidate_config.dispatcher.enabled {
            fn dispatcher_callback(handler: &ConfigHandler, components: &mut AgentComponents) {
                for dispatcher in components.dispatchers.iter() {
                    dispatcher.stop();
                }
                if handler.candidate_config.tap_mode != TapMode::Analyzer
                    && !running_in_container()
                    && !is_kernel_available_for_cgroup()
                // In the environment where cgroup is not supported, we need to check free memory
                {
                    match free_memory_check(
                        // fixme: It can skip this check because it has been checked before
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
                } else {
                    for dispatcher in components.dispatchers.iter() {
                        dispatcher.start();
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

impl ModuleConfig {
    fn get_channel_size(&self, mem_size: u64) -> usize {
        if self.tap_mode == TapMode::Analyzer {
            return 1 << 14;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 14)
    }

    fn get_flow_capacity(&self, mem_size: u64) -> usize {
        if self.tap_mode == TapMode::Analyzer {
            return self.yaml_config.flow.capacity as usize;
        }

        min((mem_size / MB / 128 * 65536) as usize, 1 << 30)
    }
}

impl YamlConfig {
    fn get_fast_path_map_size(&self, mem_size: u64) -> usize {
        if self.fast_path_map_size > 0 {
            return self.fast_path_map_size;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 20)
    }

    fn get_af_packet_blocks(&self, tap_mode: TapMode, mem_size: u64) -> usize {
        if tap_mode == TapMode::Analyzer || self.af_packet_blocks_enabled {
            self.af_packet_blocks.max(8)
        } else {
            (mem_size as usize / recv_engine::DEFAULT_BLOCK_SIZE / 16).min(128)
        }
    }
}
