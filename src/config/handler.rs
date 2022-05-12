use std::cmp::{max, min};
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{access::Map, ArcSwap};
use bytesize::ByteSize;
use flexi_logger::LoggerHandle;
use hostname;
use log::{info, warn, Level};

use super::{Config, ConfigError, IngressFlavour, KubernetesPollerType};

use crate::common::{
    enums::TapType, DEFAULT_LIBVIRT_XML_PATH, TRIDENT_MEMORY_LIMIT, TRIDENT_PROCESS_LIMIT,
    TRIDENT_THREAD_LIMIT,
};
use crate::dispatcher::BpfOptions;
use crate::proto::trident::IfMacSource;
use crate::{
    common::decapsulate::{TunnelType, TunnelTypeBitmap},
    dispatcher::recv_engine::{self, bpf, OptTpacketVersion},
    ebpf::CAP_LEN_MAX,
    flow_generator::{FlowTimeout, TcpTimeout},
    proto::trident::{self, CaptureSocketType},
    proto::{
        common::TridentType,
        trident::{SocketType, TapMode},
    },
    trident::Components,
    utils::environment::is_tt_pod,
    utils::net::{get_route_src_ip, MacAddr},
};

const MB: u64 = 1048576;
const MINUTE: Duration = Duration::from_secs(60);
const SECOND: Duration = Duration::from_secs(1);

type Access<C> = Map<Arc<ArcSwap<NewRuntimeConfig>>, NewRuntimeConfig, fn(&NewRuntimeConfig) -> &C>;

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
    pub process_threshold: u32,
    pub thread_threshold: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SenderConfig {
    pub mtu: u32,
    pub dest_ip: IpAddr,
    pub vtap_id: u16,
    pub npb_vlan_mode: trident::VlanMode,
    pub npb_dedup_enabled: bool,
    pub npb_bps_threshold: u64,
    pub npb_socket_type: trident::SocketType,
    pub compressor_socket_type: trident::SocketType,
    pub collector_socket_type: trident::SocketType,
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
    pub capture_packet_size: u32,
    pub l7_log_packet_size: u32,
    pub tunnel_type_bitmap: TunnelTypeBitmap,
    pub trident_type: TridentType,
    pub bpf_options: BpfOptions,
    pub vtap_id: u16,
    pub source_ip: IpAddr,
    pub capture_socket_type: CaptureSocketType,
    pub tap_interface_regex: String,
    pub packet_header_enabled: bool,
    pub if_mac_source: IfMacSource,
    pub analyzer_ip: IpAddr,
    pub proxy_controller_ip: IpAddr,
    pub capture_bpf: String,
    pub max_memory: u64,
    pub af_packet_blocks: usize,
    pub af_packet_version: OptTpacketVersion,
    pub tap_mode: TapMode,
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
pub struct PcapConfig {
    pub queue_size: u32,
    pub block_size_kb: u32,
    pub max_concurrent_files: u32,
    pub max_file_size_mb: u32,
    pub max_file_period: Duration,
    pub file_directory: PathBuf,
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
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub ntp_enabled: bool,
    pub max_escape: Duration,
    pub output_vlan: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfConfig {
    // 动态配置
    pub vtap_id: u16,
    pub epc_id: u32,
    pub l7_log_packet_size: usize,
    // 静态配置
    pub l7_log_session_timeout: Duration,
    pub log_path: String,
}

// Span/Trace 共用一套TypeMap
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TraceType {
    Disabled, // 业务表示关闭
    XB3,
    XB3Span,
    Uber,
    Sw6,
    Sw8,
}

impl From<&str> for TraceType {
    fn from(t: &str) -> TraceType {
        match t {
            "x-b3-trace-id" => TraceType::XB3,
            "x-b3-parentspanid" => TraceType::XB3Span,
            "uber-trace-id" => TraceType::Uber,
            "sw6" => TraceType::Sw6,
            "sw8" => TraceType::Sw8,
            _ => TraceType::Disabled,
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
    pub trace_id_origin: String,
    pub trace_id_lower: String,
    pub trace_id_with_colon: String,
    pub trace_type: TraceType,
    pub span_id_origin: String,
    pub span_id_lower: String,
    pub span_id_with_colon: String,
    pub span_type: TraceType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewRuntimeConfig {
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
    pub global_pps_threshold: u64,
}

impl Default for NewRuntimeConfig {
    fn default() -> Self {
        let default_ip = Ipv4Addr::UNSPECIFIED.into();
        let vtap_id = 0u16;
        let trident_type = TridentType::TtProcess;
        let host = hostname::get()
            .ok()
            .and_then(|c| c.into_string().ok())
            .unwrap_or_default();

        let mut conf = NewRuntimeConfig {
            diagnose: DiagnoseConfig {
                enabled: false,
                libvirt_xml_path: DEFAULT_LIBVIRT_XML_PATH.into(),
            },
            environment: EnvironmentConfig {
                max_memory: TRIDENT_MEMORY_LIMIT,
                process_threshold: TRIDENT_PROCESS_LIMIT,
                thread_threshold: TRIDENT_THREAD_LIMIT,
            },
            synchronizer: SynchronizerConfig {
                sync_interval: MINUTE,
                region_id: 0,
                pod_cluster_id: 0,
                ntp_enabled: false,
                max_escape: SECOND,
                output_vlan: 0,
            },
            stats: StatsConfig {
                interval: MINUTE,
                host: host.clone(),
            },
            global_pps_threshold: 2048,
            dispatcher: DispatcherConfig {
                capture_packet_size: 1024,
                l7_log_packet_size: 256,
                tunnel_type_bitmap: Default::default(),
                trident_type,
                bpf_options: Default::default(),
                vtap_id,
                source_ip: default_ip,
                capture_socket_type: trident::CaptureSocketType::Auto,
                tap_interface_regex: Default::default(),
                packet_header_enabled: false,
                if_mac_source: trident::IfMacSource::IfMac,
                analyzer_ip: default_ip,
                proxy_controller_ip: default_ip,
                capture_bpf: Default::default(),
                max_memory: TRIDENT_MEMORY_LIMIT,
                af_packet_blocks: 0,
                af_packet_version: OptTpacketVersion::default(),
                tap_mode: TapMode::default(),
            },
            sender: SenderConfig {
                mtu: 1500,
                dest_ip: default_ip,
                vtap_id,
                npb_vlan_mode: trident::VlanMode::None,
                npb_dedup_enabled: false,
                npb_bps_threshold: 1024,
                npb_socket_type: trident::SocketType::Tcp,
                compressor_socket_type: trident::SocketType::Tcp,
                server_tx_bandwidth_threshold: 1024,
                bandwidth_probe_interval: MINUTE,
                collector_socket_type: trident::SocketType::Tcp,
                enabled: true,
            },
            collector: CollectorConfig {
                enabled: true,
                inactive_server_port_enabled: false,
                vtap_flow_1s_enabled: false,
                l4_log_collect_nps_threshold: 1024,
                l7_metrics_enabled: true,
                trident_type,
                vtap_id,
                l4_log_store_tap_types: [false; 256],
                cloud_gateway_traffic: false,
            },
            handler: HandlerConfig {
                compressor_socket_type: trident::SocketType::Tcp,
                npb_dedup_enabled: false,
                trident_type,
            },
            pcap: PcapConfig {
                queue_size: 65536,
                block_size_kb: 64,
                max_concurrent_files: 5000,
                max_file_size_mb: 250,
                max_file_period: Duration::from_secs(300),
                file_directory: "/var/lib/pcap".into(),
            },
            platform: PlatformConfig {
                sync_interval: MINUTE,
                kubernetes_cluster_id: Default::default(),
                libvirt_xml_path: DEFAULT_LIBVIRT_XML_PATH.into(),
                kubernetes_poller_type: KubernetesPollerType::Adaptive,
                vtap_id,
                enabled: false,
                ingress_flavour: IngressFlavour::Kubernetes,
                trident_type,
                source_ip: default_ip,
                epc_id: 0,
                kubernetes_api_enabled: false,
                namespace: None,
            },
            flow: {
                FlowConfig {
                    vtap_id,
                    trident_type,
                    cloud_gateway_traffic: false,
                    collector_enabled: true,
                    l7_log_tap_types: [false; 256],
                    packet_delay: SECOND,
                    flush_interval: SECOND,
                    flow_timeout: FlowTimeout::from(TcpTimeout {
                        established: Duration::from_secs(300),
                        closing_rst: Duration::from_secs(35),
                        others: Duration::from_secs(5),
                    }),
                    ignore_tor_mac: false,
                    ignore_l2_end: false,
                    l7_metrics_enabled: true,
                    app_proto_log_enabled: true,
                    l4_performance_enabled: true,
                    l7_log_packet_size: 256,
                }
            },
            log_parser: LogParserConfig {
                l7_log_collect_nps_threshold: 1024,
                l7_log_session_aggr_timeout: Duration::from_secs(120),
                l7_log_dynamic: L7LogDynamicConfig::default(),
            },
            debug: DebugConfig {
                vtap_id,
                enabled: false,
                controller_ips: vec![],
                listen_port: 0,
            },
            log: LogConfig {
                log_level: Level::Info,
                log_threshold: 1024,
                log_retention: 7,
                rsyslog_enabled: false,
                host,
            },
            ebpf: EbpfConfig {
                vtap_id,
                epc_id: 0,
                l7_log_session_timeout: Duration::from_secs(120),
                log_path: "".to_string(),
                l7_log_packet_size: CAP_LEN_MAX,
            },
        };
        conf.collector.l4_log_store_tap_types[u16::from(TapType::Isp(2)) as usize] = true;
        conf.flow.l7_log_tap_types[u16::from(TapType::Isp(2)) as usize] = true;

        conf
    }
}

impl NewRuntimeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.synchronizer.sync_interval < Duration::from_secs(1)
            || self.synchronizer.sync_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "sync-interval {:?} not in [1s, 1h]",
                self.synchronizer.sync_interval
            )));
        }
        if self.stats.interval < Duration::from_secs(1)
            || self.stats.interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "stats-interval {:?} not in [1s, 1h]",
                self.stats.interval
            )));
        }

        // 虽然RFC 791里最低MTU是68，但是此时compressor会崩溃，
        // 所以MTU最低限定到200以确保trident能够成功运行
        if self.sender.mtu < 200 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "MTU({}) specified smaller than 200",
                self.sender.mtu
            )));
        }

        if self.synchronizer.output_vlan > 4095 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "output-vlan({}) out of range (0-4095)",
                self.synchronizer.output_vlan
            )));
        }

        if self.dispatcher.analyzer_ip.is_unspecified() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-ip({}) invalid",
                self.dispatcher.analyzer_ip
            )));
        }
        if self.dispatcher.proxy_controller_ip.is_unspecified() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-ip({}) invalid",
                self.dispatcher.proxy_controller_ip
            )));
        }

        if regex::Regex::new(&self.dispatcher.tap_interface_regex).is_err() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed tap-interface-regex({})",
                self.dispatcher.tap_interface_regex
            )));
        }

        if self.synchronizer.max_escape < Duration::from_secs(600)
            || self.synchronizer.max_escape > Duration::from_secs(86400)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max-escape-seconds {:?} not in [600s, 86400s]",
                self.synchronizer.max_escape
            )));
        }

        if self.dispatcher.capture_packet_size > 65535 || self.dispatcher.capture_packet_size < 128
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "capture packet size {} not in [128, 65535]",
                self.dispatcher.capture_packet_size
            )));
        }

        if self.collector.l4_log_store_tap_types.iter().all(|&x| !x) {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "l4-log-tap-types has tap type not in [{:?}, {:?})",
                TapType::Any,
                TapType::Max
            )));
        }

        if self.flow.l7_log_tap_types.iter().all(|&x| x) {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "l7-log-store-tap-types has tap type not in [{:?}, {:?})",
                TapType::Any,
                TapType::Max
            )));
        }

        if self.sender.collector_socket_type == trident::SocketType::RawUdp {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "invalid collector_socket_type {:?}",
                self.sender.collector_socket_type
            )));
        }

        if self.sender.npb_socket_type == trident::SocketType::Tcp {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "invalid npb_socket_type {:?}",
                self.sender.npb_socket_type
            )));
        }

        Ok(())
    }
}

pub struct ConfigHandler {
    pub static_config: Config,
    pub ctrl_ip: IpAddr,
    pub ctrl_mac: MacAddr,
    pub logger_handle: LoggerHandle,
    // need update
    pub candidate_config: NewRuntimeConfig,
    pub current_config: Arc<ArcSwap<NewRuntimeConfig>>,
}

impl ConfigHandler {
    pub fn new(
        config: Config,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        logger_handle: LoggerHandle,
    ) -> Self {
        let candidate_config = NewRuntimeConfig::default();

        let current_config = Arc::new(ArcSwap::from_pointee(candidate_config.clone()));

        Self {
            static_config: config,
            ctrl_ip,
            ctrl_mac,
            candidate_config,
            current_config,
            logger_handle,
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

    pub fn new_runtime_config(
        &self,
        conf: trident::Config,
    ) -> Result<NewRuntimeConfig, ConfigError> {
        let candidate_config = &self.candidate_config;
        let static_config = &self.static_config;

        let dest_ip = if conf.analyzer_ip().is_empty() {
            static_config.analyzer_ip.parse::<IpAddr>().unwrap()
        } else {
            conf.analyzer_ip()
                .parse::<IpAddr>()
                .unwrap_or(Ipv4Addr::UNSPECIFIED.into())
        };
        let config = NewRuntimeConfig {
            diagnose: DiagnoseConfig {
                enabled: conf.enabled(),
                libvirt_xml_path: conf.libvirt_xml_path().parse().unwrap_or_default(),
            },
            environment: EnvironmentConfig {
                max_memory: (conf.max_memory() as u64) << 20,
                process_threshold: conf.process_threshold(),
                thread_threshold: conf.thread_threshold(),
            },
            synchronizer: SynchronizerConfig {
                sync_interval: Duration::from_secs(conf.sync_interval() as u64),
                output_vlan: conf.output_vlan() as u16,
                region_id: conf.region_id(),
                pod_cluster_id: conf.pod_cluster_id(),
                ntp_enabled: conf.ntp_enabled(),
                max_escape: Duration::from_secs(conf.max_escape_seconds() as u64),
            },
            stats: StatsConfig {
                interval: Duration::from_secs(conf.stats_interval() as u64),
                host: if conf.host().is_empty() {
                    candidate_config.stats.host.clone()
                } else {
                    conf.host().to_string()
                },
            },
            global_pps_threshold: conf.global_pps_threshold(),
            dispatcher: DispatcherConfig {
                capture_packet_size: conf.capture_packet_size(),
                l7_log_packet_size: conf.l7_log_packet_size(),
                tunnel_type_bitmap: {
                    let mut tunnel_types = conf
                        .decap_type
                        .iter()
                        .map(|&t| TunnelType::try_from(t as u8).unwrap())
                        .collect::<Vec<_>>();
                    if self.static_config.decap_erspan {
                        tunnel_types.push(TunnelType::ErspanOrTeb);
                    }
                    TunnelTypeBitmap::new(&tunnel_types)
                },
                trident_type: conf.trident_type(),
                bpf_options: candidate_config.dispatcher.bpf_options.clone(),
                vtap_id: conf.vtap_id() as u16,
                source_ip: candidate_config.dispatcher.source_ip,
                capture_socket_type: conf.capture_socket_type(),
                tap_interface_regex: conf.tap_interface_regex().to_string(),
                packet_header_enabled: conf.packet_header_enabled(),
                if_mac_source: conf.if_mac_source(),
                analyzer_ip: dest_ip,
                proxy_controller_ip: if conf.proxy_controller_ip().is_empty() {
                    static_config.controller_ips[0].parse::<IpAddr>().unwrap()
                } else {
                    conf.proxy_controller_ip()
                        .parse()
                        .unwrap_or(Ipv4Addr::UNSPECIFIED.into())
                },
                capture_bpf: conf.capture_bpf().to_string(),
                max_memory: (conf.max_memory() as u64) << 24,
                af_packet_blocks: Self::get_af_packet_blocks(
                    static_config,
                    (conf.max_memory() as u64) << 24,
                ),
                af_packet_version: conf.capture_socket_type().into(),
                tap_mode: static_config.tap_mode,
            },
            sender: SenderConfig {
                mtu: conf.mtu(),
                dest_ip,
                vtap_id: conf.vtap_id() as u16,
                npb_vlan_mode: conf.npb_vlan_mode(),
                npb_dedup_enabled: conf.npb_dedup_enabled(),
                npb_bps_threshold: conf.npb_bps_threshold(),
                npb_socket_type: conf.npb_socket_type(),
                compressor_socket_type: conf.compressor_socket_type(),
                server_tx_bandwidth_threshold: conf.server_tx_bandwidth_threshold(),
                bandwidth_probe_interval: Duration::from_secs(conf.bandwidth_probe_interval()),
                collector_socket_type: conf.collector_socket_type(),
                enabled: conf.collector_enabled(),
            },
            collector: CollectorConfig {
                enabled: conf.collector_enabled(),
                inactive_server_port_enabled: conf.inactive_server_port_enabled(),
                vtap_flow_1s_enabled: conf.vtap_flow_1s_enabled(),
                l4_log_collect_nps_threshold: conf.l4_log_collect_nps_threshold(),
                l7_metrics_enabled: conf.l7_metrics_enabled(),
                trident_type: conf.trident_type(),
                vtap_id: conf.vtap_id() as u16,
                l4_log_store_tap_types: if conf.l4_log_tap_types.is_empty() {
                    candidate_config.collector.l4_log_store_tap_types
                } else {
                    let mut l4_log_tap_types = [false; 256];
                    for &tap in conf.l4_log_tap_types.iter() {
                        if tap < 256 {
                            l4_log_tap_types[tap as usize] = true;
                        }
                    }
                    l4_log_tap_types
                },
                cloud_gateway_traffic: static_config.cloud_gateway_traffic,
            },
            handler: HandlerConfig {
                compressor_socket_type: conf.compressor_socket_type(),
                npb_dedup_enabled: conf.npb_dedup_enabled(),
                trident_type: conf.trident_type(),
            },
            pcap: candidate_config.pcap.clone(),
            platform: PlatformConfig {
                sync_interval: MINUTE,
                kubernetes_cluster_id: static_config.kubernetes_cluster_id.clone(),
                libvirt_xml_path: conf.libvirt_xml_path().parse().unwrap_or_default(),
                kubernetes_poller_type: static_config.kubernetes_poller_type,
                vtap_id: conf.vtap_id() as u16,
                enabled: conf.platform_enabled(),
                ingress_flavour: static_config.ingress_flavour,
                trident_type: conf.trident_type(),
                source_ip: self.ctrl_ip,
                epc_id: conf.epc_id(),
                kubernetes_api_enabled: conf.kubernetes_api_enabled(),
                namespace: if static_config.kubernetes_namespace.is_empty() {
                    None
                } else {
                    Some(static_config.kubernetes_namespace.clone())
                },
            },
            flow: {
                let flow_config = &self.static_config.flow;

                let l7_log_tap_types = if conf.l7_log_store_tap_types.is_empty() {
                    candidate_config.flow.l7_log_tap_types
                } else {
                    let mut l7_log_tap_types = [false; 256];
                    for &tap in conf.l7_log_store_tap_types.iter() {
                        if tap < 256 {
                            l7_log_tap_types[tap as usize] = true;
                        }
                    }
                    l7_log_tap_types
                };
                FlowConfig {
                    vtap_id: conf.vtap_id() as u16,
                    trident_type: conf.trident_type(),
                    cloud_gateway_traffic: static_config.cloud_gateway_traffic,
                    collector_enabled: conf.collector_enabled(),
                    l7_log_tap_types,
                    packet_delay: static_config.packet_delay,
                    flush_interval: flow_config.flush_interval,
                    flow_timeout: FlowTimeout::from(TcpTimeout {
                        established: flow_config.established_timeout,
                        closing_rst: flow_config.closing_rst_timeout,
                        others: flow_config.others_timeout,
                    }),
                    ignore_tor_mac: flow_config.ignore_tor_mac,
                    ignore_l2_end: flow_config.ignore_l2_end,
                    l7_metrics_enabled: conf.l7_metrics_enabled(),
                    app_proto_log_enabled: !conf.l7_log_store_tap_types.is_empty(),
                    l4_performance_enabled: conf.l4_performance_enabled(),
                    l7_log_packet_size: conf.l7_log_packet_size(),
                }
            },
            log_parser: LogParserConfig {
                l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold(),
                l7_log_session_aggr_timeout: static_config.l7_log_session_aggr_timeout,
                l7_log_dynamic: L7LogDynamicConfig {
                    proxy_client_origin: conf.http_log_proxy_client().to_string(),
                    proxy_client_lower: conf.http_log_proxy_client().to_string().to_lowercase(),
                    proxy_client_with_colon: format!("{}:", conf.http_log_proxy_client()),

                    x_request_id_origin: conf.http_log_x_request_id().to_string(),
                    x_request_id_lower: conf.http_log_x_request_id().to_string().to_lowercase(),
                    x_request_id_with_colon: format!("{}:", conf.http_log_x_request_id()),

                    trace_id_origin: conf.http_log_trace_id().to_string(),
                    trace_id_lower: conf.http_log_trace_id().to_string().to_lowercase(),
                    trace_id_with_colon: format!("{}:", conf.http_log_trace_id()),
                    trace_type: conf.http_log_trace_id().into(),

                    span_id_origin: conf.http_log_span_id().to_string(),
                    span_id_lower: conf.http_log_span_id().to_string().to_lowercase(),
                    span_id_with_colon: format!("{}:", conf.http_log_span_id()),
                    span_type: conf.http_log_span_id().into(),
                },
            },
            debug: DebugConfig {
                vtap_id: conf.vtap_id() as u16,
                enabled: conf.debug_enabled(),
                controller_ips: static_config
                    .controller_ips
                    .iter()
                    .map(|c| c.parse::<IpAddr>().unwrap())
                    .collect(),
                listen_port: static_config.debug_listen_port,
            },
            log: LogConfig {
                log_level: match conf.log_level().to_lowercase().as_str() {
                    "error" => log::Level::Error,
                    "warn" | "warning" => log::Level::Warn,
                    "info" => log::Level::Info,
                    "debug" => log::Level::Debug,
                    "trace" => log::Level::Trace,
                    _ => log::Level::Info,
                },
                log_threshold: conf.log_threshold(),
                log_retention: conf.log_retention(),
                rsyslog_enabled: conf.rsyslog_enabled(),
                host: if conf.host().is_empty() {
                    candidate_config.log.host.clone()
                } else {
                    conf.host().to_string()
                },
            },
            ebpf: EbpfConfig {
                vtap_id: conf.vtap_id() as u16,
                epc_id: conf.epc_id(),
                l7_log_session_timeout: static_config.l7_log_session_aggr_timeout,
                log_path: static_config.ebpf_log_file.clone(),
                l7_log_packet_size: CAP_LEN_MAX.min(conf.l7_log_packet_size() as usize),
            },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn on_config(
        &mut self,
        mut new_config: NewRuntimeConfig,
    ) -> Vec<fn(&ConfigHandler, &mut Components)> {
        let candidate_config = &mut self.candidate_config;
        let static_config = &mut self.static_config;
        let mut callbacks: Vec<fn(&ConfigHandler, &mut Components)> = vec![];
        //TODO dispatcher on_config_change 要迁移过来
        let mut restart_dispatcher = false;
        let source_ip = match get_route_src_ip(&new_config.dispatcher.analyzer_ip) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "analyzer_ip({}) get route src ip failed: {}",
                    new_config.dispatcher.analyzer_ip, e
                );
                candidate_config.dispatcher.source_ip
            }
        };

        if candidate_config.dispatcher != new_config.dispatcher {
            let mut reset_bpf = false;
            if candidate_config.dispatcher.analyzer_ip != new_config.dispatcher.analyzer_ip {
                info!("find source-ip {}", source_ip);
                reset_bpf = true;
            }

            if candidate_config.dispatcher.if_mac_source != new_config.dispatcher.if_mac_source {
                if static_config.tap_mode != TapMode::Local {
                    info!(
                        "if_mac_source set to {:?}",
                        new_config.dispatcher.if_mac_source
                    );
                }
            }

            if candidate_config.dispatcher.capture_packet_size
                != new_config.dispatcher.capture_packet_size
            {
                if static_config.tap_mode == TapMode::Analyzer || cfg!(target_os = "windows") {
                    todo!()
                }
            }

            if candidate_config.dispatcher.capture_socket_type
                != new_config.dispatcher.capture_socket_type
            {
                restart_dispatcher = !cfg!(target_os = "windows");
            }

            if candidate_config.dispatcher.proxy_controller_ip
                != new_config.dispatcher.proxy_controller_ip
            {
                reset_bpf = true;
            }

            if candidate_config.dispatcher.capture_bpf != new_config.dispatcher.capture_bpf {
                reset_bpf = true;
            }

            if candidate_config.dispatcher.max_memory != new_config.dispatcher.max_memory {
                if Self::get_af_packet_blocks(static_config, new_config.dispatcher.max_memory)
                    != Self::get_af_packet_blocks(
                        static_config,
                        candidate_config.dispatcher.max_memory,
                    )
                    || Self::get_fast_path_map_size(static_config, new_config.dispatcher.max_memory)
                        != Self::get_fast_path_map_size(
                            static_config,
                            candidate_config.dispatcher.max_memory,
                        )
                    || Self::get_channel_size(static_config, new_config.dispatcher.max_memory)
                        != Self::get_channel_size(
                            static_config,
                            candidate_config.dispatcher.max_memory,
                        )
                    || Self::get_flow_capacity(static_config, new_config.dispatcher.max_memory)
                        != Self::get_flow_capacity(
                            static_config,
                            candidate_config.dispatcher.max_memory,
                        )
                {
                    restart_dispatcher = true;
                    info!("max_memory change, restart dispatcher");
                }
            }
            if reset_bpf {
                let bpf_syntax = bpf::Builder {
                    is_ipv6: self.ctrl_ip.is_ipv6(),
                    vxlan_port: static_config.vxlan_port,
                    controller_port: static_config.controller_port,
                    controller_tls_port: static_config.controller_tls_port,
                    proxy_controller_ip: candidate_config.dispatcher.proxy_controller_ip,
                    analyzer_source_ip: source_ip,
                }
                .build_pcap_syntax();
                new_config.dispatcher.bpf_options.bpf_syntax = bpf_syntax;
            }

            info!(
                "dispatcher config change from {:#?} to {:#?}",
                candidate_config.dispatcher, new_config.dispatcher
            );
            candidate_config.dispatcher = new_config.dispatcher;
        }

        if candidate_config.log != new_config.log {
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
            candidate_config.log = new_config.log;
            //TODO Rsyslog stuff
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
            if candidate_config.environment.max_memory != new_config.environment.max_memory {
                if static_config.tap_mode != TapMode::Analyzer {
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
            info!(
                "environment config change from {:#?} to {:#?}",
                candidate_config.environment, new_config.environment
            );

            candidate_config.environment = new_config.environment;
        }

        if candidate_config.global_pps_threshold != new_config.global_pps_threshold {
            candidate_config.global_pps_threshold = new_config.global_pps_threshold;

            fn leaky_bucket_callback(handler: &ConfigHandler, components: &mut Components) {
                match handler.static_config.tap_mode {
                    TapMode::Analyzer => {
                        components.rx_leaky_bucket.set_rate(None);
                        info!("global pps set ulimit when tap_mode=analyzer");
                    }
                    _ => {
                        components
                            .rx_leaky_bucket
                            .set_rate(Some(handler.candidate_config.global_pps_threshold));
                        info!(
                            "global pps threshold change to {}",
                            handler.candidate_config.global_pps_threshold
                        );
                    }
                }
            }
            callbacks.push(leaky_bucket_callback);
        }

        if cfg!(target_os = "windows") && static_config.tap_mode != TapMode::Analyzer {
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
                if static_config.tap_mode != TapMode::Analyzer {
                    restart_dispatcher = true;
                }
            }

            if candidate_config.sender.npb_dedup_enabled != new_config.sender.npb_dedup_enabled {
                if static_config.tap_mode != TapMode::Analyzer {
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
                if static_config.tap_mode != TapMode::Analyzer {
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

        if restart_dispatcher {
            fn dispatcher_callback(_: &ConfigHandler, components: &mut Components) {
                for dispatcher in components.dispatchers.iter() {
                    dispatcher.stop();
                }
                for dispatcher in components.dispatchers.iter() {
                    dispatcher.start();
                }
            }
            callbacks.push(dispatcher_callback);
        }

        // deploy updated config
        self.current_config
            .store(Arc::new(candidate_config.clone()));

        callbacks
    }

    fn get_fast_path_map_size(config: &Config, mem_size: u64) -> usize {
        if config.fast_path_map_size > 0 {
            return config.fast_path_map_size;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 20)
    }

    fn get_channel_size(config: &Config, mem_size: u64) -> usize {
        if config.tap_mode == TapMode::Analyzer {
            return 1 << 14;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 14)
    }

    fn get_flow_capacity(config: &Config, mem_size: u64) -> usize {
        if config.tap_mode == TapMode::Analyzer {
            return config.flow.capacity as usize;
        }

        min((mem_size / MB / 128 * 65536) as usize, 1 << 30)
    }

    fn get_af_packet_blocks(config: &Config, mem_size: u64) -> usize {
        if config.tap_mode == TapMode::Analyzer || config.af_packet_blocks_enabled {
            config.af_packet_blocks.max(8)
        } else {
            (mem_size as usize / recv_engine::DEFAULT_BLOCK_SIZE / 16).min(128)
        }
    }
}
