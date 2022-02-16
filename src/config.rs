use std::convert::TryFrom;
use std::fs;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::common::TapType;
use crate::proto::{common, trident};

#[cfg(unix)]
const DEFAULT_LOG_FILE: &str = "/var/log/trident/trident.log";
#[cfg(windows)]
const DEFAULT_LOG_FILE: &str = "C:\\Deepflow\\trident\\log\\trident.log";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("controller-ips is empty")]
    ControllerIpsEmpty,
    #[error("controller-ips invalid")]
    ControllerIpsInvalid,
    #[error("runtime config invalid: {0}")]
    RuntimeConfigInvalid(String),
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Config {
    pub controller_ips: Vec<String>,
    pub controller_port: u16,
    pub controller_tls_port: u16,
    pub genesis_rpc_port: u16,
    pub genesis_rpc_tls_port: u16,
    pub log_file: String,
    #[serde(with = "LevelDef")]
    pub log_level: log::Level,
    pub profiler: bool,
    pub afpacket_blocks_enabled: bool,
    pub afpacket_blocks: u32,
    pub enable_debug_stats: bool,
    pub analyzer_dedup_disabled: bool,
    pub default_tap_type: u32,
    pub debug_listen_port: u16,
    pub enable_qos_bypass: bool,
    pub fast_path_map_size: u32,
    pub first_path_level: u32,
    pub src_interfaces: Vec<String>,
    #[serde(with = "TapModeDef")]
    pub tap_mode: trident::TapMode,
    pub mirror_traffic_pcp: u16,
    pub controller_cert_file_prefix: String,
    pub vtap_group_id_request: String,
    pub pcap: PcapConfig,
    pub flow: FlowGeneratorConfig,
    pub flow_queue_size: u32,
    pub quadruple_queue_size: u32,
    pub analyzer_queue_size: u32,
    #[serde(rename = "ovs-dpdk-enable")]
    pub ovs_dpdk_enabled: bool,
    pub dpdk_pmd_core_id: u32,
    pub dpdk_ring_port: String,
    pub xflow_collector: XflowGeneratorConfig,
    pub vxlan_port: u16,
    pub collector_sender_queue_size: u32,
    pub collector_sender_queue_count: u32,
    pub flow_sender_queue_size: u32,
    pub flow_sender_queue_count: u32,
    #[serde(with = "humantime_serde")]
    pub second_flow_extra_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub packet_delay: Duration,
    pub triple: TripleMapConfig,
    pub kubernetes_poller_type: KubernetesPollerType,
    pub decap_erspan: bool,
    pub analyzer_ip: String,
    pub kubernetes_cluster_id: String,
    pub ingress_flavour: IngressFlavour,
}

impl Config {
    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Config, io::Error> {
        let contents = fs::read_to_string(path)?;
        let mut c: Config = serde_yaml::from_str(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        c.controller_ips = c
            .controller_ips
            .drain(..)
            .filter_map(|addr| Config::resolve_domain(&addr))
            .collect();

        if c.pcap.queue_size < 1 << 16 {
            c.pcap.queue_size = 1 << 16;
        }
        if c.pcap.queue_count < 1 || c.pcap.queue_count > 16 {
            c.pcap.queue_count = 1;
        } else {
            c.pcap.queue_count = c.pcap.queue_count.next_power_of_two();
        }
        if c.flow.flush_interval < Duration::from_secs(1)
            || c.flow.flush_interval > Duration::from_secs(10)
        {
            c.flow.flush_interval = Duration::from_secs(1);
        }
        if c.flow_queue_size < 1 << 16 {
            c.flow_queue_size = 1 << 16;
        }
        if c.quadruple_queue_size < 1 << 18 {
            c.quadruple_queue_size = 1 << 18;
        }
        if c.analyzer_queue_size < 1 << 17 {
            c.analyzer_queue_size = 1 << 17;
        }
        if c.collector_sender_queue_size == 0 {
            c.collector_sender_queue_size = if c.tap_mode == trident::TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            }
        }
        if c.flow_sender_queue_size == 0 {
            c.flow_sender_queue_size = if c.tap_mode == trident::TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            }
        }
        if c.packet_delay < Duration::from_secs(1) || c.packet_delay > Duration::from_secs(10) {
            c.packet_delay = Duration::from_secs(1);
        }
        if c.first_path_level < 1 || c.first_path_level > 16 {
            c.first_path_level = 8;
        }
        if let Err(e) = c.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
        }
        Ok(c)
    }

    // resolve domain name (without port) to ip address
    fn resolve_domain(addr: &str) -> Option<String> {
        format!("{}:1", addr)
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.next())
            .map(|addr| addr.ip().to_string())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.controller_ips.is_empty() {
            return Err(ConfigError::ControllerIpsEmpty);
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            controller_ips: vec!["127.0.0.1".into()],
            controller_port: 20035,
            controller_tls_port: 20135,
            genesis_rpc_port: 20036,
            genesis_rpc_tls_port: 20136,
            log_file: DEFAULT_LOG_FILE.into(),
            log_level: log::Level::Info,
            profiler: false,
            afpacket_blocks_enabled: false,
            afpacket_blocks: 0,
            enable_debug_stats: false,
            analyzer_dedup_disabled: false,
            default_tap_type: 3,
            debug_listen_port: 0,
            enable_qos_bypass: false,
            fast_path_map_size: 0,
            first_path_level: 0,
            src_interfaces: vec!["dummy0".into(), "dummy1".into()],
            tap_mode: trident::TapMode::Local,
            mirror_traffic_pcp: 0,
            controller_cert_file_prefix: "".into(),
            vtap_group_id_request: "".into(),
            pcap: Default::default(),
            flow: Default::default(),
            flow_queue_size: 65536,
            quadruple_queue_size: 262144,
            analyzer_queue_size: 131072,
            ovs_dpdk_enabled: false,
            dpdk_pmd_core_id: 0,
            dpdk_ring_port: "dpdkr0".into(),
            xflow_collector: Default::default(),
            vxlan_port: 4789,
            // default size changes according to tap_mode
            collector_sender_queue_size: 0,
            collector_sender_queue_count: 1,
            // default size changes according to tap_mode
            flow_sender_queue_size: 0,
            flow_sender_queue_count: 1,
            second_flow_extra_delay: Duration::from_secs(0),
            packet_delay: Duration::from_secs(1),
            triple: Default::default(),
            kubernetes_poller_type: KubernetesPollerType::Adaptive,
            decap_erspan: false,
            analyzer_ip: "".into(),
            kubernetes_cluster_id: "".into(),
            ingress_flavour: IngressFlavour::Kubernetes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(remote = "log::Level", rename_all = "kebab-case")]
enum LevelDef {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "trident::TapMode")]
enum TapModeDef {
    #[serde(rename = "0")]
    Local,
    #[serde(rename = "1")]
    Mirror,
    #[serde(rename = "2")]
    Analyzer,
    #[serde(rename = "3")]
    Decap,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct PcapConfig {
    pub enabled: bool,
    pub queue_size: u32,
    pub queue_count: u32,
    pub tcpip_checksum: bool,
    pub block_size_kb: u32,
    pub max_concurrent_files: u32,
    pub max_file_size_mb: u32,
    pub max_directory_size_gb: u32,
    pub disk_free_space_margin_gb: u32,
    #[serde(with = "humantime_serde")]
    pub max_file_period: Duration,
    pub file_directory: String,
    pub server_port: u32,
}

impl Default for PcapConfig {
    fn default() -> Self {
        PcapConfig {
            enabled: false,
            queue_size: 65536,
            queue_count: 1,
            tcpip_checksum: false,
            block_size_kb: 64,
            max_concurrent_files: 5000,
            max_file_size_mb: 250,
            max_directory_size_gb: 100,
            disk_free_space_margin_gb: 10,
            max_file_period: Duration::from_secs(300),
            file_directory: "/var/lib/pcap".into(),
            server_port: 20205,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct FlowGeneratorConfig {
    // tcp timeout config
    #[serde(with = "humantime_serde")]
    pub established_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub closing_rst_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub others_timeout: Duration,

    #[serde(rename = "flow-slots-size")]
    pub hash_slots: u32,
    #[serde(rename = "flow-count-limit")]
    pub capacity: u32,
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    #[serde(rename = "flow-sender-throttle")]
    pub sender_throttle: u32,
    #[serde(rename = "flow-aggr-queue-size")]
    pub aggr_queue_size: u32,

    pub ignore_tor_mac: bool,
    pub ignore_l2_end: bool,
}

impl Default for FlowGeneratorConfig {
    fn default() -> Self {
        FlowGeneratorConfig {
            established_timeout: Duration::from_secs(300),
            closing_rst_timeout: Duration::from_secs(35),
            others_timeout: Duration::from_secs(5),

            hash_slots: 131072,
            capacity: 1048576,
            flush_interval: Duration::from_secs(1),
            sender_throttle: 1024,
            aggr_queue_size: 65535,

            ignore_tor_mac: false,
            ignore_l2_end: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct XflowGeneratorConfig {
    pub sflow_ports: Vec<String>,
    pub netflow_ports: Vec<String>,
}

impl Default for XflowGeneratorConfig {
    fn default() -> Self {
        XflowGeneratorConfig {
            sflow_ports: vec!["6343".into()],
            netflow_ports: vec!["2055".into()],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct TripleMapConfig {
    #[serde(rename = "flow-slots-size")]
    pub hash_slots: u32,
    pub capacity: u32,
}

impl Default for TripleMapConfig {
    fn default() -> Self {
        TripleMapConfig {
            hash_slots: 65536,
            capacity: 1048576,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesPollerType {
    Adaptive,
    Active,
    Passive,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IngressFlavour {
    Kubernetes,
    Openshift,
}

#[derive(Debug)]
pub struct RuntimeConfig<'a> {
    pub enabled: bool,
    pub max_cpus: u32,
    pub max_memory: u64,
    pub sync_interval: Duration,
    pub stats_interval: Duration,
    pub global_pps_threshold: u64,
    pub tap_interface_regex: &'a str,
    pub host: &'a str,
    pub rsyslog_enabled: bool,
    pub output_vlan: u16,
    pub mtu: u32,
    pub npb_bps_threshold: u64,
    pub collector_enabled: bool,
    pub l4_log_store_tap_types: &'a Vec<u32>,
    pub packet_header_enabled: bool,
    pub platform_enabled: bool,
    pub server_tx_bandwidth_threshold: u64,
    pub bandwidth_probe_interval: Duration,
    pub npb_vlan_mode: trident::VlanMode,
    pub npb_dedup_enabled: bool,
    pub if_mac_source: trident::IfMacSource,
    pub vtap_flow_1s_enabled: bool,
    pub debug_enabled: bool,
    pub log_threshold: u32,
    pub log_level: log::Level,
    pub analyzer_ip: &'a str,
    pub max_escape: Duration,
    pub proxy_controller_ip: &'a str,
    pub vtap_id: u16,
    pub collector_socket_type: trident::SocketType,
    pub compressor_socket_type: trident::SocketType,
    pub npb_socket_type: trident::SocketType,
    pub trident_type: common::TridentType,
    pub capture_packet_size: u32,
    pub inactive_server_port_enabled: bool,
    pub libvirt_xml_path: &'a str,
    pub l7_log_packet_size: u32,
    pub l4_log_collect_nps_threshold: u64,
    pub l7_log_collect_nps_threshold: u64,
    pub l7_metrics_enabled: bool,
    pub l7_log_store_tap_types: &'a Vec<u32>,
    pub decap_type: trident::DecapType,
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub log_retention: u32,
    pub capture_socket_type: trident::CaptureSocketType,
    pub process_threshold: u32,
    pub thread_threshold: u32,
    pub capture_bpf: &'a str,
}

impl RuntimeConfig<'_> {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.sync_interval < Duration::from_secs(1)
            || self.sync_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "sync-interval {:?} not in [1s, 1h]",
                self.sync_interval
            )));
        }
        if self.stats_interval < Duration::from_secs(1)
            || self.stats_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "stats-interval {:?} not in [1s, 1h]",
                self.stats_interval
            )));
        }

        // 虽然RFC 791里最低MTU是68，但是此时compressor会崩溃，
        // 所以MTU最低限定到200以确保trident能够成功运行
        if self.mtu < 200 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "MTU({}) specified smaller than 200",
                self.mtu
            )));
        }

        if self.output_vlan > 4095 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "output-vlan({}) out of range (0-4095)",
                self.output_vlan
            )));
        }

        if self.analyzer_ip.parse::<IpAddr>().is_err() || self.analyzer_ip == "0.0.0.0" {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-ip({}) invalid",
                self.analyzer_ip
            )));
        }

        if regex::Regex::new(&self.tap_interface_regex).is_err() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed tap-interface-regex({})",
                self.tap_interface_regex
            )));
        }

        if self.max_escape < Duration::from_secs(600)
            || self.max_escape > Duration::from_secs(86400)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max-escape-seconds {:?} not in [600s, 86400s]",
                self.max_escape
            )));
        }

        if self.proxy_controller_ip.parse::<IpAddr>().is_err()
            || self.proxy_controller_ip == "0.0.0.0"
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "proxy-controller-ip({}) invalid",
                self.proxy_controller_ip
            )));
        }

        if self.capture_packet_size > 65535 || self.capture_packet_size < 128 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "capture packet size {} not in [128, 65535]",
                self.capture_packet_size
            )));
        }

        if self
            .l4_log_store_tap_types
            .iter()
            .any(|&x| x > u16::from(TapType::Max) as u32)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "l4-log-tap-types has tap type not in [{:?}, {:?})",
                TapType::Any,
                TapType::Max
            )));
        }

        if self
            .l7_log_store_tap_types
            .iter()
            .any(|&x| x > u16::from(TapType::Max) as u32)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "l7-log-store-tap-types has tap type not in [{:?}, {:?})",
                TapType::Any,
                TapType::Max
            )));
        }
        Ok(())
    }
}

impl<'a> TryFrom<&'a trident::Config> for RuntimeConfig<'a> {
    type Error = io::Error;

    fn try_from(conf: &trident::Config) -> Result<RuntimeConfig, io::Error> {
        let rc = RuntimeConfig {
            enabled: conf.enabled(),
            max_cpus: conf.max_cpus(),
            max_memory: (conf.max_memory() as u64) << 20,
            sync_interval: Duration::from_secs(conf.sync_interval() as u64),
            stats_interval: Duration::from_secs(conf.stats_interval() as u64),
            global_pps_threshold: conf.global_pps_threshold(),
            tap_interface_regex: conf.tap_interface_regex(),
            host: conf.host(),
            rsyslog_enabled: conf.rsyslog_enabled(),
            output_vlan: (conf.output_vlan() & 0xFFFFFFFF) as u16,
            mtu: conf.mtu(),
            npb_bps_threshold: conf.npb_bps_threshold(),
            collector_enabled: conf.collector_enabled(),
            l4_log_store_tap_types: &conf.l4_log_tap_types,
            packet_header_enabled: conf.packet_header_enabled(),
            platform_enabled: conf.platform_enabled(),
            server_tx_bandwidth_threshold: conf.server_tx_bandwidth_threshold(),
            bandwidth_probe_interval: Duration::from_secs(conf.bandwidth_probe_interval()),
            npb_vlan_mode: conf.npb_vlan_mode(),
            npb_dedup_enabled: conf.npb_dedup_enabled(),
            if_mac_source: conf.if_mac_source(),
            vtap_flow_1s_enabled: conf.vtap_flow_1s_enabled(),
            debug_enabled: conf.debug_enabled(),
            log_threshold: conf.log_threshold(),
            log_level: match conf.log_level().to_lowercase().as_str() {
                "error" => log::Level::Error,
                "warn" => log::Level::Warn,
                "info" => log::Level::Info,
                "debug" => log::Level::Debug,
                "trace" => log::Level::Trace,
                _ => log::Level::Info,
            },
            analyzer_ip: conf.analyzer_ip(),
            max_escape: Duration::from_secs(conf.max_escape_seconds() as u64),
            proxy_controller_ip: conf.proxy_controller_ip(),
            vtap_id: (conf.vtap_id() & 0xFFFFFFFF) as u16,
            collector_socket_type: conf.collector_socket_type(),
            compressor_socket_type: conf.compressor_socket_type(),
            npb_socket_type: conf.npb_socket_type(),
            trident_type: conf.trident_type(),
            capture_packet_size: conf.capture_packet_size(),
            inactive_server_port_enabled: conf.inactive_server_port_enabled(),
            libvirt_xml_path: conf.libvirt_xml_path(),
            l7_log_packet_size: conf.l7_log_packet_size(),
            l4_log_collect_nps_threshold: conf.l4_log_collect_nps_threshold(),
            l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold(),
            l7_metrics_enabled: conf.l7_metrics_enabled(),
            l7_log_store_tap_types: &conf.l7_log_store_tap_types,
            decap_type: conf.decap_type(),
            region_id: conf.region_id(),
            pod_cluster_id: conf.pod_cluster_id(),
            log_retention: conf.log_retention(),
            capture_socket_type: conf.capture_socket_type(),
            process_threshold: conf.process_threshold(),
            thread_threshold: conf.thread_threshold(),
            capture_bpf: conf.capture_bpf(),
        };
        rc.validate()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        Ok(rc)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn read_yaml_file() {
        // TODO: improve test cases
        let c = Config::load_from_file("config/trident.yaml").expect("failed loading config file");
        assert_eq!(c.controller_ips.len(), 1);
        assert_eq!(&c.controller_ips[0], "127.0.0.1");
    }
}
